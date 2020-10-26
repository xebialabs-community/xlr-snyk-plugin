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
from xlrelease.HttpRequest import HttpRequest
import org.slf4j.Logger as Logger
import org.slf4j.LoggerFactory as LoggerFactory
from org.apache.http.client import ClientProtocolException
from java.lang import String

'''
Calls Snyk API to execute/query against the Snyk defined project using TOKEN based access as defined by Snyk
'''

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


    def snyk_projectcheck(self, variables):
        endpoint = '/org/{}/project/{}'.format(variables['groupId'], variables['projId'])

        self.logger.info("Getting scan results using groupId:{} and projectId:{}".format(variables['groupId'], variables['projId']))
        
        resp = self.api_call("GET", endpoint, headers=variables['headers'])
        data = json.loads(resp.getResponse())
        self.logger.warn("Results: {}".format(data))

        return data['issueCountsBySeverity']
        

    def snyk_getprojects(self, variables):
        endpoint = '/org/{}/projects'

        self.logger.info("Getting scan results for all projects using groupId:{}".format(variables['groupId']))

        resp = self.api_call("GET", endpoint, headers=variables['headers'])
        data = json.loads(resp.getResponse())
        self.logger.warn("Results: {}".format(data))

        projects_data = {}
        for project in data['org']['projects']:
            projects_data[project['id']] = {'name': project['name'], 'issueCountsBySeverity': project['issueCountsBySeverity']}
            
        return projects_data