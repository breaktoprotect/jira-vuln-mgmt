"""
Author  : Jeremy Soh @breaktoprotect
Date    : 22 Oct 2022
Description:
- Simple API client to the Jira REST API services
- This API client is designed for Jira cloud API v3
"""
import os
import requests
from requests.auth import HTTPBasicAuth

from api_v3_endpoints import *

#? Configuration
API_HOSTNAME = os.environ['API_HOSTNAME']
HEADERS = {
    "Accept": "application/json"
}
AUTH = HTTPBasicAuth("jeremyspk@gmail.com", os.environ['API_ACCESS_TOKEN'])

def search_project_id(key):
    key = key.upper()
    params = {
        "query": key
    }

    response = requests.get(API_HOSTNAME + API_SEARCH_PROJECTS, params=params, headers=HEADERS, auth=AUTH)

    if response.status_code == 200:
        for item in response.json()['values']:
            if key == item['key']:
                return item['id']

    return None

def get_matching_issues(project_id, query):
    params = {
        "currentProjectId":project_id,
        "query":query
    }
    response = requests.get(API_HOSTNAME + API_SEARCH_ISSUES, params=params, headers=HEADERS,auth=AUTH)
    
    matched_issue_key_list = []
    for section in response.json()['sections']:
        for issue in section['issues']:
            matched_issue_key_list.append(issue['key'])

    return matched_issue_key_list

#* Retrieve essential fields from an issue
#  Fields -> 
def get_issue_fields(issue_key):
    params = {
        "fields":"*navigable"
    }

    response = requests.get(API_HOSTNAME + API_GET_ISSUE_FIELDS + issue_key, params=params, headers=HEADERS,auth=AUTH)

    return response.json()


#! Testing only
if __name__ == "__main__":
    #get_all_issues(10001)

    # 1. Obtain project ID by key
    project_id = search_project_id("VuLN") 

    # 2. Get interested issues
    issue_list = get_matching_issues(project_id, "sql") 
    
    print(issue_list)

    # 3. Get an issue fields
    issue_A = get_issue_fields('VULN-1')
    print(issue_A)

