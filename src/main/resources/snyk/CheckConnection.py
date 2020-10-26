#
# Copyright 2020 Digital.ai
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#                                                                                                                    
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.                                                                                                          
#                                                                                                                    
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import requests

'''
Calls Snyk API to see if we can connect
'''

if token is None:
    print("No Snyk token provided.")
    sys.exit(1)

if base_url is None:
    print("No Snyk base url provided.")
    sys.exit(1)

headers = {
        "Content-Type": "application/json",
        "Authorization": "token {}".format(token)
}

resp = requests.get(base_url, headers=headers)

if resp.ok:
    print(resp.json())
    print("\n")
else:
    # Something went wrong
    print("HTTP {} - {}, Message {}".format(resp.status_code, resp.reason, resp.text))
    raise Exception("HTTP {} - {}, Message {}".format(resp.status_code, resp.reason, resp.text))