#
# Copyright 2020 Digital.ai
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#                                                                                                                    
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.                                                                                                          
#                                                                                                                    
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import json
import sets
from xlrelease.HttpRequest import HttpRequest
import org.slf4j.Logger as Logger
import org.slf4j.LoggerFactory as LoggerFactory
from org.apache.http.client import ClientProtocolException
from java.lang import String

'''
Calls Snyk API to execute/query against the Snyk defined project using TOKEN based access as defined by Snyk
'''

HTTP_SUCCESS = sets.Set([200, 201, 202, 203, 204, 205, 206, 207, 208])
HTTP_ERROR = sets.Set([400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410,412, 413, 414, 415])

class SnykClient(object):
    def __init__(self, server):
        self.logger = LoggerFactory.getLogger("com.xebialabs.snyk-plugin")
        if server in [None, ""]:
            raise Exception("server is undefined")
                
        self.http_request = HttpRequest(server)


    @staticmethod
    def get_client(server):
        return SnykClient(server)


    def parse_output(self, lines):
        result_output = ""
        for line in lines:
            result_output = "\n".join([result_output, line])
        return result_output


    def api_call(self, method, endpoint, **options):
        self.logger.debug("DEBUG:{}".format(endpoint))
        try:
            options["method"] = method.upper()
            options["context"] = endpoint
            response = self.http_request.doRequest(**options)
        except ClientProtocolException:
            raise Exception("URL is not valid")
        if not response.isSuccessful():
            raise Exception(
                "HTTP response code %s (%s)"
                % (response.getStatus(), response.errorDump())
            )
        return response


    def snyk_projectcompliance(self, variables):
        endpoint = '/org/{}/project/{}'.format(variables['orgId'], variables['projId'])
        severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'ignore': 0}
        issues = False
        self.logger.info("Getting scan results using orgId:{} and projectId:{}".format(variables['orgId'], variables['projId']))
        
        resp = self.api_call("GET", endpoint, headers=variables['headers'])
        data = json.loads(resp.getResponse())
        if resp.getStatus() in HTTP_SUCCESS:
            self.logger.warn("Results: {}".format(data))

            # severity is set in the Task definition
            fail_level = severity_levels[variables['severity']]
            for key, val in data['issueCountsBySeverity'].items():
                if val > 0 and fail_level <= severity_levels[key]:
                    err_msg = "Project:{} has compliance issues - {}:{}".format(variables['projId'], key, val)
                    self.logger.error(err_msg)
                    self.setLastError(err_msg)
                    print(err_msg)
                    raise Exception(err_msg)
                if val > 0:
                    issues = True

            if issues and variables['severity'] == 'ignore':
                err_msg = "Project has issues that match or exceed severity level: {}".format(variables['severity'])
                print(err_msg)
                self.logger.error(err_msg)
            
            return data['issueCountsBySeverity']
        else:
            self.logBadReturnCodes(data)

        self.throw_error(resp)


    def snyk_getprojects(self, variables):
        endpoint = '/org/{}/projects'.format(variables['orgId'])

        self.logger.info("Getting scan results for all projects using orgId:{}".format(variables['orgId']))

        resp = self.api_call("GET", endpoint, headers=variables['headers'])
        data = json.loads(resp.getResponse())
        if resp.getStatus() in HTTP_SUCCESS:
            self.logger.debug("Results: {}".format(data))

            projects_data = []
            for project in data['projects']:
                projects_data.append({
                    'id': project['id'],
                    'name': project['name'],
                    'high': project['issueCountsBySeverity']['high'],
                    'medium': project['issueCountsBySeverity']['medium'],
                    'low': project['issueCountsBySeverity']['low']
                })
                
            self.logger.debug("Projects Data:{}".format(projects_data))
            return projects_data
        else:
            self.logBadReturnCodes(data)

        self.throw_error(resp)


    def logBadReturnCodes(self, data):
        if ('returnCode' in data) & ('reasonCode' in data) & ('messages' in data):
            self.logger.error("Return Code = {}".format(data['returnCode']))
            self.logger.error("Reason Code = {}".format(data['reasonCode']))
            self.logger.error("Message     = {}".format(data['messages']))
        else:
            tb = self.getLastError()
            self.logger.error("Return Codes EXCEPTION \n================\n%s\n=================".format(tb))
            self.logger.error("REAL BAD RETURN OBJECT!!!!")
            self.setLastError("{}\nREAL BAD RETURN OBJECT!!!!".format(tb))
            raise Exception(500)


    def setLastError(self, error):
        self.error = error


    def getLastError(self):
        return self.error


    def throw_error(self, resp):
        self.logger.error("Error from Snyk, HTTP Return: {}\n".format(resp.getStatus()))
        raise Exception(resp.getStatus())