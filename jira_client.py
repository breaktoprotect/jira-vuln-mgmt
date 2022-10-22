"""
Author  : Jeremy S. @breaktoprotect
Date    : 22 Oct 2022
Description:
- Simple API client to the Jira REST API services
- This API client is designed for Jira cloud API v3
"""
import os
import requests
from requests.auth import HTTPBasicAuth

import jira_vuln_model as MODEL

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

def search_custom_fields():
    params = {
        "type":"custom",
        "maxResults": 50 # 50 is default and also max 
    }
    response = requests.get(API_HOSTNAME + API_SEARCH_FIELDS, params=params, headers=HEADERS,auth=AUTH)

    print(response.json())

def populate_custom_fields():
    pass

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

#* Retrieve Metadata for Create Issue
def get_metadata_create_issue(project_key):
    params = {
        "projectKeys":[project_key],
        "expand":"projects.issuetypes.fields"
    }
    response = requests.get(API_HOSTNAME + API_CREATE_ISSUE_METADATA, params=params, headers=HEADERS,auth=AUTH)

    return response.json()

#* Retrieve essential fields from an issue
#  Fields -> 
def get_issue_fields(issue_key):
    params = {
        "fields":"*navigable"
    }

    response = requests.get(API_HOSTNAME + API_ISSUES + issue_key, params=params, headers=HEADERS,auth=AUTH)

    return response.json()

#* Create a vulnerability jira issue
def create_jira_vuln(vuln):
    json_post = {
        "fields": {
            "summary": vuln.summary,
            "issuetype": {
                "id": 10008
            },
            "project": {
                "id": vuln.project_id
            },
            "reporter": { "id": "5b2f82cc55b2312db2b866e6"}
            
        }
    }
    # Additional custom fields
    #TODO json_post['']

    this_headers = {
        "Content-Type":"application/json"
    }

    response = requests.post(API_HOSTNAME + API_ISSUES, json=json_post, headers=this_headers,auth=AUTH)

    return response.text


#! Testing only
if __name__ == "__main__":
    #Testing import
    import sys

    #get_all_issues(10001)

    # Get metadata
    """ metadata_json = get_metadata_create_issue("vuln")
    for issuetype in metadata_json['projects'][0]['issuetypes']:
        for key in issuetype['fields'].keys():
            if issuetype['fields'][key]['required'] == True:
                print("{KEY:20} - {NAME}".format(KEY=key, NAME=issuetype['fields'][key]['name'])) """

    # Test create issue
    vuln = MODEL.Vuln(summary="test summary", project_id=search_project_id("VuLN") )
    print(vuln.project_id)
    print(create_jira_vuln(vuln))

    sys.exit(-1)

    # 1. Init 
    # Obtain project ID by key
    project_id = search_project_id("VuLN") 

    # Search custom fields
    print(search_custom_fields())

    # 2. Get interested issues
    issue_list = get_matching_issues(project_id, "sql") 
    
    print(issue_list)

    # 3. Get an issue fields
    issue_A = get_issue_fields('VULN-1')
    print(issue_A)

