
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
Calls Snyk API to query for projects owned by OrgId
'''
v = vars()

import org.slf4j.Logger as Logger
import org.slf4j.LoggerFactory as LoggerFactory
import httplib
import ssl
from com.xhaus.jyson import JysonCodec as json

logger = LoggerFactory.getLogger('snyk-plugin')
logger.debug("Starting GetProjects.py")

base_url = str(valueProvider.server.url)
token = str(valueProvider.server.token)
orgId = str(valueProvider.server.orgId)
snyk_host = str(base_url.split("/")[2])
path = '/' + str(base_url.split("/")[3]) + '/' + str(base_url.split("/")[4]) + '/org/' + orgId + '/projects'
headers = {
    "Content-Type": "application/json",
    "Authorization": "token {}".format(token)
}

uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
connection = httplib.HTTPSConnection(snyk_host, context=uv_context)
connection.request('GET', path, None, headers=headers)
response = connection.getresponse()
response_string = response.read()
connection.close()

obj_methods = [method_name for method_name in dir(httplib)
                  if callable(getattr(httplib, method_name))]
#response_json = json.loads(response_string)

projList = []
response_json = json.loads(response_string)
for project in response_json['projects']:
    projList.append(project['name'])

items = []
for key in httplib.__dict__:
    items.append(key)

#result = items
#result = obj_methods
#result = [type(v), snyk_host, token, orgId, path, len(response_string)]
result = projList
