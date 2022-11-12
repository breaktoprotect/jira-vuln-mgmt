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

import jira_vuln_model as MODEL
import custom_fields as CUSTOM

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

def jql_search_issues(jql):
    params = {
        "jql": jql,
        "maxResults": 999999
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

    response = requests.get(API_HOSTNAME + API_ISSUES + issue_key, params=params, headers=HEADERS,auth=AUTH)

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

    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['Finding Source']] = {
        "value": vuln.finding_source
    }
    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['Affected Component']] = [
        {
            "name": vuln.affected_component
        }
    ]

    json_post["fields"][CUSTOM.CUSTOM_FIELDS_TO_ID['Issue Digest']] = vuln.issue_digest

    this_headers = {
        "Content-Type":"application/json"
    }

    response = requests.post(API_HOSTNAME + API_ISSUES, json=json_post, headers=this_headers,auth=AUTH)

    return response

#? Helper functions
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

#! Testing only
if __name__ == "__main__":
    pass

