"""
Author  : Jeremy S. (@breaktoprotect)
Date    : 22 Oct 2022
Description:
- Logic for implementing vulnerability ticket creation via Jira
"""
import jira_client as JIRA_CLIENT
import custom_params as CUSTOM
import jira_vuln_model as JIRA_MODEL
import hashlib
import datetime
import pytz
import sys

#* ***** Core Features *****
#* Report multiple vuln issues using a list of vuln objects on Jira
def report_vuln_list(vuln_list, affected_component, finding_source):
    # 0. Verification(s)
    # a. Check if both current vuln list and existing issues are both empty
    existing_issue = get_any_one_existing_issue(affected_component, finding_source)
    if (not vuln_list) and (not existing_issue):
        print("[*] No vulnerabilities to report. There are also no existing issues to auto close. Operation exited.")
        return 0

    # 1. Initialize by populating all essential values from Jira
    init_all_fields_id()

    # 2. Duplicate check - ignore vulns that are already reported; update duplicates' 'Last Reported Date'
    duplicate_issues_list, closed_duplicate_issues_list = get_list_of_duplicate_issues(vuln_list)

    if duplicate_issues_list or closed_duplicate_issues_list:
        new_vuln_list = get_new_issues_list(vuln_list, duplicate_issues_list, closed_duplicate_issues_list)
        update_last_reported_issues_list(duplicate_issues_list)
        reopen_status_issue_id_list(closed_duplicate_issues_list)
    else:
        new_vuln_list = [] 

    """ no_duplicate_vuln_list = []
    duplicate_issue_id_list = []
    for vuln in vuln_list:
        value = get_duplicate_issue(vuln)
        if not value:
            no_duplicate_vuln_list.append(vuln)
        else:
            duplicate_issue_id_list.append(value) """

    # 3. Close vulns that are no longer found
    fixed_issue_id_list = get_fixed_issue_id_list(vuln_list, affected_component, finding_source)
    if len(fixed_issue_id_list) > 0:
        auto_close_issue_list(fixed_issue_id_list)

    # 4. Report each vuln on the list
    for vuln in new_vuln_list:
        report_vuln(vuln)

#* Report a single vuln issue on Jira
def report_vuln(vuln):
    response = JIRA_CLIENT.create_jira_vuln(vuln, CUSTOM.ISSUE_TYPE_ID)

    if response.status_code >= 300:
        print("[!] Error reporting vuln. Error response:", response.text)
    else:
        print("[*] Created. Response:", response.text)

#* Create a vuln instance
#   reported_date: YYYY-MM-DD
def create_vuln(summary, description, reporter_email, source, cve_id, raw_severity, first_reported_date, last_reported_date, affected_component, issue_digest, project_key=CUSTOM.PROJECT_KEY):
    project_id = JIRA_CLIENT.search_project_id(CUSTOM.PROJECT_KEY)
    reporter_id = get_reporter_account_id(reporter_email)

    vuln = JIRA_MODEL.Vuln(
            summary=summary, 
            project_id=project_id,  
            description=description,
            reporter_id=reporter_id,
            finding_source=source,
            cve_id=cve_id,
            raw_severity=raw_severity,
            first_reported_date=first_reported_date,
            last_reported_date=last_reported_date,
            affected_component=affected_component,
            issue_digest=issue_digest
    )
    return vuln

#* Duplication check
#  Criteria: If issue has the same cve/vuln ID on the same component on the same line, consider it as a duplicate
#  Enhanced criteria: Ignores 'Auto Closed' or 'Closed' - not considered as duplicate and a new issue will be created.
#TODO currently it is 1 new issue per request to verify existence of existing finding - is there a better way?
def get_duplicate_issue(vuln):
    this_issue_digest = calc_issue_digest(vuln.summary, vuln.description, vuln.cve_id, vuln.affected_component)

    #response = JIRA_CLIENT.jql_search_issues('project = "VULN" AND "Issue Digest[Short text]" ~ "{DIGEST}" AND status NOT IN ("Auto Closed", "Closed")'.format(DIGEST=this_issue_digest))
    response = JIRA_CLIENT.jql_search_issues('project = "VULN" AND "Issue Digest[Short text]" ~ "{DIGEST}"'.format(DIGEST=this_issue_digest)) # Get all issues of this digest
    # Check if issue existed
    if 'issues' in response.json().keys():
        if len(response.json()['issues']) > 0:
            return response.json()['issues'][0]['id']
        else:
            return False

#* Duplication check V2
#  Criteria: If issue has the same cve/vuln ID on the same component on the same line, consider it as a duplicate
def get_list_of_duplicate_issues(vuln_list):
    # Verify that it's not empty
    if len(vuln_list) < 1:
        return None, None

    # 1. Get list of issues belonging to the same affected component and finding source
    jql = 'project = "VULN" AND "Affected Component[Short text]" ~ {AFFECTED_COMPONENT} AND "Finding Source[Short text]" ~ {FINDING_SOURCE}'.format(AFFECTED_COMPONENT=vuln_list[0].affected_component, FINDING_SOURCE=vuln_list[0].finding_source)
    issues_list = JIRA_CLIENT.jql_get_all_jira_issues(jql)

    # 2. Create two list - one duplicate list (non-closed issues) ; another duplicate list of issues that 'Auto Closed' / 'Closed'
    duplicate_issues = []
    closed_duplicate_issues = []
    for issue in issues_list:
        for vuln in vuln_list:
            if issue['fields'][CUSTOM.CUSTOM_FIELDS_TO_ID['Issue Digest']] == vuln.issue_digest:           
                # If status is 'OPEN'
                if issue['fields']['status']['name'] == 'Open':
                    duplicate_issues.append(issue)            

                # if status is 'AUTO CLOSED' or 'CLOSED'
                if issue['fields']['status']['name'] in ['Auto Closed', 'Closed']:
                    closed_duplicate_issues.append(issue)      

    return duplicate_issues, closed_duplicate_issues

#* Get list of new issues by comparing current vuln_list with duplicate issues list
def get_new_issues_list(vuln_list, duplicate_issues_list, closed_dup_issues_list):
    first_pass_vuln_list = []
    for vuln in vuln_list:
        if not vuln.issue_digest in list(map(lambda issue: issue['fields'][CUSTOM.CUSTOM_FIELDS_TO_ID['Issue Digest']], duplicate_issues_list)):
            first_pass_vuln_list.append(vuln)

    final_pass_vuln_list = []
    for vuln in first_pass_vuln_list:
        if not vuln.issue_digest in list(map(lambda issue: issue['fields'][CUSTOM.CUSTOM_FIELDS_TO_ID['Issue Digest']], closed_dup_issues_list)):
            final_pass_vuln_list.append(vuln)

    return final_pass_vuln_list

#* Update the list of vuln's 'Last Reported Date' field with current time
def update_last_reported_issues_list(dup_issues_list):
    for issue_id in list(map(lambda issue: issue['id'], dup_issues_list)):
        # Update the 'Last Reported Date'
        JIRA_CLIENT.update_issue_custom_field(issue_id, "Last Reported Date", get_current_date())
    return

#* Update the list of vuln's if status is 'AUTO CLOSED' or 'CLOSED', set it to 'OPEN'
def reopen_status_issue_id_list(closed_dup_issue_list):
    # Check if list is empty, if not get the transition_id for 'Open'
    if closed_dup_issue_list:
        transition_id = JIRA_CLIENT.get_transition_id(closed_dup_issue_list[0]['id'],'Open')
    else:
        return

    for issue_id in list(map(lambda issue: issue['id'], closed_dup_issue_list)):
        JIRA_CLIENT.set_status_open(issue_id, transition_id)
    return    

#* Get findings that are no longer reported this time - delta between current scan and existing Jira issues
#  Criteria: If issue no longer exist in current scans given that it belongs to the same affected component and it's by the same tool-type (e.g. Trivy-SCA) , it should be closed
def get_fixed_issue_id_list(this_vuln_list, affected_component, finding_source):
    # Obtain all existing
    jql = 'project = "vuln" AND "Affected Component[Short text]" ~ "{AFFECTED_COMPONENT}" AND "Finding Source[Short text]" ~ "{FINDING_SOURCE}" AND status NOT IN ("Auto Closed", "Closed") ORDER BY created DESC'.format(AFFECTED_COMPONENT=affected_component, FINDING_SOURCE=finding_source)
    jira_issues_list = JIRA_CLIENT.jql_get_all_jira_issues(jql, field_list=[CUSTOM.CUSTOM_FIELDS_TO_ID["Issue Digest"]])

    # Compare the current-to-be-reported list vs. existing-on-jira list
    fixed_vuln_id_list = [] # Keep a record 'Issue Digest' of fixed issues

    this_vuln_issue_digest_list = get_list_of_field(this_vuln_list, "issue_digest")
    for issue in jira_issues_list:
        if issue['fields'][CUSTOM.CUSTOM_FIELDS_TO_ID['Issue Digest']] not in this_vuln_issue_digest_list:
            fixed_vuln_id_list.append(issue['id'])

    return fixed_vuln_id_list

#* Auto Close An Issue
def auto_close_issue_list(issue_id_list):
    transition_id = JIRA_CLIENT.get_transition_id(issue_id_list[0], "Auto Closed")

    for issue_id in issue_id_list:
        JIRA_CLIENT.set_status_auto_closed(issue_id, transition_id)

    return

#* Get one of any existing issue based on 'affected_component' and 'finding_source'
def get_any_one_existing_issue(affected_component, finding_source):
    jql = 'project = "vuln" AND "Affected Component[Short text]" ~ "{AFFECTED_COMPONENT}" AND "Finding Source[Short text]" ~ "{FINDING_SOURCE}" AND status NOT IN ("Auto Closed", "Closed") ORDER BY created DESC'.format(AFFECTED_COMPONENT=affected_component, FINDING_SOURCE=finding_source)
    jira_issues_list = JIRA_CLIENT.jql_get_all_jira_issues(jql, field_list=[CUSTOM.CUSTOM_FIELDS_TO_ID["Issue Digest"]])

    if not jira_issues_list:
        return None
    else:
        return jira_issues_list[0]
        
#? ***** Helper functions *****
#? Prepare any required information such as field keys, options for each fields, etc. 
#  This is to avoid hardcoding specific field keys (e.g. hardcoding customfield_10011 for 'Reported Date' field)
def init_all_fields_id(project_key=CUSTOM.PROJECT_KEY):
    # Get the dict of metadata fields
    metadata_dict = JIRA_CLIENT.get_metadata_create_issue(project_key)

    for issuetype in metadata_dict['projects'][0]['issuetypes']:
        meta_fields_dict = issuetype['fields']

    # Populate fields key 
    populate_custom_fields_key(meta_fields_dict)

    # Populate issuetype id
    populate_issuetype_id(project_key)

#? Find the key for each of the corresponding field's name
def populate_custom_fields_key(meta_fields_dict, custom_fields_id_dict=CUSTOM.CUSTOM_FIELDS_TO_ID): # pass by reference
    for field in CUSTOM.CUSTOM_FIELDS_TO_ID:
        for meta_field in meta_fields_dict:
            if meta_fields_dict[meta_field]['name'] == field:
                CUSTOM.CUSTOM_FIELDS_TO_ID[field] = meta_fields_dict[meta_field]['key']
                print("[+] Custom Field {FIELD} param key populated.".format(FIELD=field))
    return

#? Find issuetype id for key 'VULN'
def populate_issuetype_id(key):
    projects = JIRA_CLIENT.get_metadata_create_issue(key)['projects']
    for project in projects:
        if project['key'].lower() == key.lower():
            for issue_type in project['issuetypes']:
                if issue_type['name'] == 'Vulnerability':
                    CUSTOM.ISSUE_TYPE_ID = issue_type['id']
                    print("[+] Issue Type ID established:", CUSTOM.ISSUE_TYPE_ID)

#? Obtain reporter's account ID based on email address
def get_reporter_account_id(email_address):
    json_data = JIRA_CLIENT.search_users_by_email(email_address)

    return json_data[0]['accountId']

#? Translate the qualitative rating based on the CVSS quantitative figure between 0 to 10
def severity_num_to_qualitative(num_rating):
    case = lambda x: num_rating < x
    if case(4):
        return "Low"
    elif case(7):
        return "Medium"
    elif case(9):
        return "High"
    else:
        return "Critical"

#? Calculate a message digest for issue
def calc_issue_digest(summary, description, cve_id, affected_component):
    hash = hashlib.sha256()
    overall_str = (summary + str(description) + cve_id + affected_component).encode('utf-8')
    hash.update(overall_str)
    
    return hash.hexdigest()

#? Retrieve list of a specified field (e.g. Issue Digest)
def get_list_of_field(vuln_list, field_name):
    field_list = []
    for vuln in vuln_list:
        field_list.append(vuln[field_name])

    return field_list

#? Generate a date string e.g. 2012-12-30 of GTM now.
def get_current_date(country="Asia/Singapore"):
    timezone = pytz.timezone(country)
    current_date = datetime.datetime.now(timezone).strftime('%Y-%m-%d')

    return current_date

#? Check if string is in camelCase format
def is_camel_case(text):
    # Alphanumeric check
    if not text.isalnum():
        return False
    
    # Ensure it contains at least an upper and lower case
    if text == text.lower() or text == text.upper():
        return False

    return True

#! Testing only
if __name__ == "__main__":
    init_all_fields_id("VULN")
    print(CUSTOM.CUSTOM_FIELDS_TO_ID)

    # Get all issues
    """ 
    query = ""
    all_issues_list = JIRA_CLIENT.jql_search_issues('project="VULN" AND status != "Closed"')
    print(all_issues_list)
    print("length of all_issue_list:", len(all_issues_list)) """

    # Test
    """ project_id = JIRA_CLIENT.search_project_id("vuln")
    vuln = JIRA_MODEL.Vuln(project_id='10001', summary='DS002_Misconfiguration', description=[{'type': 'text', 'text': 'Running containers with &#39;root&#39; user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a &#39;USER&#39; statement to the Dockerfile.'}, {'type': 'text', 'text': '\n\n'}, {'type': 'text', 'text': 'Artifact: Dockerfile\nType: dockerfile\nVulnerability DS002\nSeverity: HIGH\nMessage: Specify at least 1 USER command in Dockerfile with non-root user as argument\nLink: [DS002](https://avd.aquasec.com/misconfig/ds002)'}, {'type': 'text', 'text': '\n\n'}, {'type': 'text', 'text': 'Affected component: \nDockerfile (from Line: 1 to 1)\n'}], reporter_id='5b2f82cc55b2312db2b866e6', finding_source='Trivy', cve_id='DS002', raw_severity='High', first_reported_date='2022-11-03', affected_component='App A', issue_digest="cd4047db6316da4f66dcbaa5f546796bcdf9bf063b41f45c174a3047d8df003d")

    print("is_duplicate_finding():", is_duplicate_finding(vuln)) """
    

    # Test get_all_jira_issues(project_key)
    """ import json
    jql = 'project = "{PROJECT_KEY}" AND "Affected Component[Short text]" ~ "breaktoprotect/test-pipeline-alpha@main" ORDER BY created DESC'.format(PROJECT_KEY="vuln")
    all_issues_list = JIRA_CLIENT.jql_get_all_jira_issues(jql, field_list=[CUSTOM.CUSTOM_FIELDS_TO_ID["Issue Digest"]])
    print(all_issues_list)
    print("length of all_issues_list:", len(all_issues_list)) """

    issue_id = "10201"
    JIRA_CLIENT.update_issue_custom_field(issue_id, "Last Reported Date", datetime.datetime.utcnow().strftime('%Y-%m-%d'))
