"""
Author  : Jeremy S. @breaktoprotect
Date    : 22 Oct 2022
Description:
- Simple API client to the Jira REST API services
- This API client is designed for Jira cloud API v3
"""
from email import header
import json
import os
import requests
from requests.auth import HTTPBasicAuth
import html
import sys

import jira_vuln_model as MODEL
import custom_params as CUSTOM

from api_v3_endpoints import *

#? Configuration
API_HOSTNAME = os.environ['API_HOSTNAME']
HEADERS = {
    "Accept": "application/json"
}
AUTH = HTTPBasicAuth("jeremyspk@gmail.com", os.environ['API_ACCESS_TOKEN'])

#? Symbols escape list
TO_ESCAPE_LIST = [{
        'original': 'â€¦',
        'replacement': '...'
    }]

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

def search_users_by_email(query):
    response = requests.get(API_HOSTNAME + API_SEARCH_USERS + "?query=" + query, headers=HEADERS, auth=AUTH)

    return response.json() 

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
    response = requests.get(API_HOSTNAME + API_PICK_ISSUES, params=params, headers=HEADERS,auth=AUTH)
    
    matched_issue_key_list = []
    for section in response.json()['sections']:
        for issue in section['issues']:
            matched_issue_key_list.append(issue['key'])

    return matched_issue_key_list

def jql_search_issues(jql, field_list=["*all"], start_at = 0, max_results = 100, ):
    params = {
        "jql": jql,
        "maxResults": max_results,
        "fields": field_list,
        "startAt": start_at
    }
    response = requests.post(API_HOSTNAME + API_JQL_SEARCH_ISSUES, json=params, headers=HEADERS, auth=AUTH)

    return response
    

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

    response = requests.get(API_HOSTNAME + API_ISSUE + issue_key, params=params, headers=HEADERS,auth=AUTH)

    return response.json()

#* Create a vulnerability jira issue
def create_jira_vuln(vuln):
    # Minimum fields to post the jira
    json_post = {
        "fields": {
            "summary": html.unescape(vuln.summary),
            "description": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": html_unescape_list_field(vuln.description)
                    }
                ]
            },
            "issuetype": {
                "id": 10008
            },
            "project": {
                "id": vuln.project_id
            },
            "reporter": { 
                "id": vuln.reporter_id
            }
        }
    }
    # Additional fields including custom
    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['CVE ID']] = vuln.cve_id
    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['Raw Severity']] = {
        "value": vuln.raw_severity
    }
    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['First Reported Date']] = vuln.first_reported_date
    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['Last Reported Date']] = vuln.last_reported_date
    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['Finding Source']] = vuln.finding_source
    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['Affected Component']] = vuln.affected_component
    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['Issue Digest']] = vuln.issue_digest

    this_headers = {
        "Content-Type":"application/json"
    }

    response = requests.post(API_HOSTNAME + API_ISSUE, json=json_post, headers=this_headers,auth=AUTH)

    return response

#* Get Workflow Transition ID for a specific transition
def get_transition_id(issue_id, name_of_transition):
    response = requests.get(API_HOSTNAME + API_ISSUE + issue_id + "/transitions", headers=HEADERS,auth=AUTH)

    #debug
    print(response.text)

    for transition in response.json()['transitions']:
        if name_of_transition == transition['name']:
            return transition['id']

    return -1

#* Perform Workflow Transition to change status via Transition ID (e.g. Auto Closed)
def set_status(issue_id, transition_id):
    json_post = {
        "transition": {
            "id": transition_id
        },
        "update": {
            "comment": [
                {
                    "add": {
                        "body": {
                            "type": "doc",
                            "version": 1,
                            "content": [
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "text": "Issue is no longer present and has been automatically closed.",
                                            "type": "text"
                                        }
                                    ]
                                }

                            ]
                        }
                    }
                }
            ]
        },
        "fields": {
            "resolution": {
                "name": "Done"
            }
        }

    }

    response = requests.post(API_HOSTNAME + API_ISSUE + issue_id + "/transitions", json=json_post, headers=HEADERS,auth=AUTH)

    #debug
    print("set_status() - Status: " + str(response.status_code) + " - response.text:", response.text)

    if response.status_code < 300:
        return True
    else:
        return False

#* Update a custom field value of an issue
# https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-issueidorkey-put
def update_issue_custom_field(issue_id, name_of_custom_field, value_of_custom_field):
    json_data = {
        "fields": {
            CUSTOM.CUSTOM_FIELDS_TO_ID[name_of_custom_field]: value_of_custom_field
        }
    }
    response = requests.put(API_HOSTNAME + API_ISSUE + issue_id + "/", json=json_data, headers=HEADERS,auth=AUTH)

    #debug
    print(response.text, response.status_code)

#? ######################## Helper functions ########################
#? Iteratively escape fields in a list
def html_unescape_list_field(the_list):
    unescaped_list = []
    for text in the_list:
        field_dict = {}
        for field in text:
            # Custom Escape list 
            for to_escape in TO_ESCAPE_LIST:
                field_dict[field] = text[field].replace(to_escape['original'], to_escape['replacement'])

            field_dict[field] = html.unescape(field_dict[field])

        unescaped_list.append(field_dict)
    
    return unescaped_list

#? Retrieve all Jira issues using pagination technique (due to max 100 (cloud) or 1000 (on-prem) results limit)
def jql_get_all_jira_issues(jql, field_list=["*all"]):
    # Config
    page_size = 5 # Jira cloud max is 100, 50 is default

    # Get total number of issues
    try:
        response = jql_search_issues(jql, field_list=field_list, start_at=0, max_results=page_size)
        total_num_issues = response.json()['total']

        # Iteratively get all issues
        all_issues_list = []
        current_index = 0

        while(current_index < total_num_issues):
            response = jql_search_issues(jql, field_list=field_list, start_at=current_index, max_results=page_size)
            all_issues_list.extend(response.json()['issues'])
            current_index += page_size

        return all_issues_list
    except:
        e = sys.exc_info()[0]
        print("[!] Fatal exception in jql_get_all_jira_issues(jql, field_list).Response status code:", response.status_code)
        print("    Response:", response.text)
        return


#! Testing only
if __name__ == "__main__":
    pass

    # Test Get Transitions
    """ issue_id = "10203"
    transition_id = get_transition_id(issue_id, "Auto Closed")
    print(transition_id) """
    #set_status(issue_id, transition_id)
