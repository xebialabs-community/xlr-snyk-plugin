#
# Copyright <YEAR> <COPYRIGHT HOLDER>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#                                                                                                                    
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.                                                                                                          
#                                                                                                                    
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

from __future__ import unicode_literals
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
    orgId = None
    projects = []

    def __init__(self, server):
        self.logger = LoggerFactory.getLogger("com.xebialabs.snyk-plugin")
        if server in [None, ""]:
            raise Exception("server is undefined")
                
        self.orgId = server['orgId']
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


    def set_projects(self, headers):
        endpoint = '/org/{}/projects'.format(self.orgId)

        self.logger.info("Getting scan results for all projects using orgId:{}".format(self.orgId))

        resp = self.api_call("GET", endpoint, headers=headers)
        data = json.loads(resp.getResponse())
        if resp.getStatus() in HTTP_SUCCESS:
            self.logger.debug("Results: {}".format(data))

            self.projects = data['projects']
            
        else:
            self.logBadReturnCodes(data)
            self.throw_error(resp)


    def get_project(self, headers, projectName):
        projectId = None

        for project in self.projects:
            if project['name'] == projectName:
                projectId = project['id']
                break

        if not projectId:
            raise Exception("Exiting - cannot find projectId for project:{}".format(projectName))

        endpoint = '/org/{}/project/{}/aggregated-issues'.format(self.orgId, projectId)
        values = """
        {
            "filters": {
                "types": [
                    "vuln",
                    "license"
                ]
            }
        }
        """

        self.logger.debug("Getting aggregated project issues using orgId:{} and projId:{}".format(self.orgId, projectId))
        self.logger.debug("Using endpoint:{}".format(endpoint))

        resp = self.api_call("POST", endpoint, data=values, headers=headers)
        data = json.loads(resp.getResponse())

        self.logger.debug("Got response:{}".format(resp.getStatus()))
        if resp.getStatus() in HTTP_SUCCESS:
            self.logger.debug("getproject Results: {}".format(data))

            issueData = {'vuln': {'high': 0, 'medium': 0, 'low': 0}, 'license': {'high': 0, 'medium': 0, 'low': 0}}

            for issue in data['issues']:
                self.logger.debug("Issue type:{} and severity:{}".format(issue['issueType'], issue['issueData']['severity']))

                if issue['issueType'] in issueData:
                    if issue['issueData']['severity'] in issueData[issue['issueType']]:
                        issueData[issue['issueType']][issue['issueData']['severity']] = issueData[issue['issueType']][issue['issueData']['severity']] + 1
                    else:
                        self.logger.debug("Issue severity:{} NOT FOUND IN 'issueData' with issueType:{}".format(issue['issueData']['severity'], issue['issueType']))
                        issueData[issue['issueType']] = {issue['issueData']['severity']: 1}
                else:
                    self.logger.debug("Issue type:{} NOT FOUND IN 'issueData'".format(issue['issueType']))
                    issueData[issue['issueType']] = {issue['issueData']['severity']: 1}

            self.logger.info("Returning issueData from get_project")
            return {'issues': issueData}

        else:
            self.logBadReturnCodes(data)

        self.throw_error(resp)


    def get_issues(self, variables):
        self.logger.info("Getting scan results for all projects using orgId:{} and issueType:{}".format(variables['orgId'], variables['issueType']))

        issue_data = []
        for project in self.projects:
            project_issue_data = self.get_project(variables['headers'], project['name'])
            issue_data.append({
                'id': project['id'],
                'name': project['name'],
                'high': project_issue_data['issues'][variables['issueType']]['high'],
                'medium': project_issue_data['issues'][variables['issueType']]['medium'],
                'low': project_issue_data['issues'][variables['issueType']]['low']
            })
                
        self.logger.info("Returning project issues data from get_issues")
        return issue_data
        

    def get_organizations(self, variables):
        endpoint = '/orgs'

        self.logger.debug("Getting organization results for the defined access token")

        resp = self.api_call("GET", endpoint, headers=variables['headers'])
        data = json.loads(resp.getResponse())
        if resp.getStatus() in HTTP_SUCCESS:
            self.logger.debug("Results: {}".format(data))

            return data
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
            self.logger.error("Return Codes EXCEPTION \n================\n{}\n=================".format(tb))
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