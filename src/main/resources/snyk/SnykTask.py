
#
# Copyright <YEAR> <COPYRIGHT HOLDER>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

'''
Calls Snyk API to execute/query against the Snyk defined project using TOKEN based access as defined by Snyk
'''

import snyk.Snyk

if classReload:
    reload(snyk.Snyk)

from snyk.Snyk import SnykClient
import org.slf4j.LoggerFactory as LoggerFactory
import org.slf4j.Logger as Logger

logger = LoggerFactory.getLogger("Snyk")

headers = {
            "Content-Type": "application/json",
            "Authorization": "token {}".format(server['token'])

        }

logger.info("Get Snyk Client - pass server")
snyk = SnykClient.get_client(server)

logger.info("Setup projects data")
snyk.set_projects(headers)

logger.info("Get project data for project: {}".format(projectName))
issue_data = snyk.get_project(headers, projectName)
logger.debug("Return 'resp' data (should be a list of projects with issues): {}".format(issue_data))

for key, val in issue_data.items():
    locals()[key] = val

if severity != 'ignore':
    if issue_data['issues']['vuln'][severity] > 0 or issue_data['license']['vuln'][severity] > 0:
        raise Exception("Exiting - Issues with project:'{}' meeting severity level:'{}' Issues:{}".format(projectName, severity, issue_data['issues']))