import requests
  
API_KEY = '3e1a4b98-750c-431a-bbd6-4b600409dd60'
ORG_KEY = '2f49febc-d075-4ebe-b9e8-daa34eae6b07'
base_url = 'https://snyk.io/api/v1/'
#endpoint = '/org/shorawitz-x8m/projects'
endpoint = '/test/GitHub/saltstack/salt'

##
# enpoint: orgs, org/:id/projects, test/:packageManager/:packageName/:packageVersion
def get_endpoint(base_url, endpoint, API_KEY):
    print("Access Snyk endpoint...")

    headers = {'Authorization': 'token ' + API_KEY}
    resp = requests.get(base_url + endpoint, headers=headers)

    if resp.ok:
        #print(resp.json())
        return resp
    else:
        # Something went wrong
        print("HTTP %i - %s, Message %s" % (resp.status_code, resp.reason, resp.text))
        return False


def main():
    resp = get_endpoint(base_url, endpoint, API_KEY)

    if resp and type(resp.json()) == dict:
        print("We got a dict return")
        print(resp.json())
    else:
        print("Not what we expected!")


## Run it

print "Scan completed"
