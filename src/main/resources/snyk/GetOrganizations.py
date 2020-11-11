
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
Calls Snyk API to query for organizations accessible by TOKEN
'''

""" import snyk.Snyk

if classReload:
    reload(snyk.Snyk)

from snyk.Snyk import SnykClient
import org.slf4j.LoggerFactory as LoggerFactory
import org.slf4j.Logger as Logger

logger = LoggerFactory.getLogger("Snyk")

if server is None:
    raise Exception("Missing server configuration item!")

snyk = SnykClient.get_client(server)
headers = {
            "Content-Type": "application/json",
            "Authorization": "token {}".format(server['token'])

        }

logger.debug("Call Snyk Method: snyk_getorganizations")

call = getattr(snyk, 'snyk_getorganizations')
result = call(locals()) """


""" import requests

def get_orgs(server, token):
    '''
    Retrive project info using "id" or "name" attribute
    '''

    print("Getting organizations from Snyk API")

    url = 'https://snyk.io/api/v1/ogs'
    headers = {
        "Content-Type": "application/json",
        "Authorization": "token {}".format(token)
        }

    

    try:
        resp = requests.get(url, headers=headers)
        return resp
    except ClientProtocolException:
            raise Exception("URL is not valid")
    if not resp.isSuccessful():
        raise Exception(
            "HTTP response code %s (%s)"
            % (resp.getStatus(), resp.errorDump())
        )


result = get_orgs(server, token) """

print("Starting GetOrganizations")

