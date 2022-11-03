"""
Author  : Jeremy S. (@breaktoprotect)
Date    : 22 Oct 2022
Description:
- Logic for implementing vulnerability ticket creation via Jira
"""
import jira_client as JIRA_CLIENT
import custom_fields as CUSTOM
import jira_vuln_model as JIRA_MODEL
import hashlib

#* ***** Core Features *****
#* Report multiple vuln issues using a list of vuln objects on Jira
def report_vuln_list(vuln_list, project_key):
    # 1. Initialize by populating all essential values from Jira
    init_all_fields_id(project_key)
    """ project_id = JIRA_CLIENT.search_project_id(project_key)
    all_list_of_issues = get_matching_issues(project_id, "")  """#! Empty string means get all issues? Check again

    # 2. Duplicate check - ignore vulns that are already reported
    no_duplicate_vuln_list = []
    for vuln in vuln_list:
        if not is_duplicate_finding(vuln):
            no_duplicate_vuln_list.append(vuln)

    # 3. Close vulns that are no longer found

    # 4. Report each vuln on the list
    #debug
    print("vuln to report:", no_duplicate_vuln_list)

    for vuln in no_duplicate_vuln_list:
        report_vuln(vuln)


#* Report a single vuln issue on Jira
def report_vuln(vuln):
    response = JIRA_CLIENT.create_jira_vuln(vuln)

    #debug
    print("Vuln() instance:",vuln)
    print("response status code:", response.status_code)

    if response.status_code >= 300:
        print("[!] Error reporting vuln. Error response:", response.text)
    else:
        print("[*] Created. Response:", response.text)

#* Create a vuln instance
#   reported_date: YYYY-MM-DD
def create_vuln(summary, project_key, description, reporter_email, source, cve_id, raw_severity, reported_date, component, issue_digest):
    project_id = JIRA_CLIENT.search_project_id(project_key)
    reporter_id = get_reporter_account_id(reporter_email)

    vuln = JIRA_MODEL.Vuln(
            summary=summary, 
            project_id=project_id,  
            description=description,
            reporter_id=reporter_id,
            source=source,
            cve_id=cve_id,
            raw_severity=raw_severity,
            reported_date=reported_date,
            component=component,
            issue_digest=issue_digest
    )
    return vuln

#* 

#* Duplication check
#  Criteria: If issue has the same cve/vuln ID on the same component on the same line, consider it as a duplicate
#TODO currently it is 1 new issue per request to verify existence of existing finding - is there a better way?
def is_duplicate_finding(vuln):
    this_issue_digest = calc_issue_digest(vuln.summary, vuln.description, vuln.cve_id, vuln.component)

    response = JIRA_CLIENT.jql_search_issues('project = "VULN" AND "Issue Digest[Short text]" ~ "{DIGEST}"'.format(DIGEST=this_issue_digest))

    #debug
    print(response.json())
    print(response.status_code)

    # Check if issue existed
    if 'issues' in response.json().keys():
        if len(response.json()['issues']) > 0:
            return True
        else:
            return False
        


#? ***** Helper functions *****
#* Prepare any required information such as field keys, options for each fields, etc. 
#  This is to avoid hardcoding specific field keys (e.g. hardcoding customfield_10011 for 'Reported Date' field)
def init_all_fields_id(PROJECT_KEY):
    # Get the dict of metadata fields
    metadata_dict = JIRA_CLIENT.get_metadata_create_issue(PROJECT_KEY)

    for issuetype in metadata_dict['projects'][0]['issuetypes']:
        meta_fields_dict = issuetype['fields']

    # 1. Populate fields key 
    populate_custom_fields_key(meta_fields_dict)

    # 2. Populate field 'source' options id
    #populate_source_options_id(meta_fields_dict)

def populate_custom_fields_key(meta_fields_dict, custom_fields_id_dict=CUSTOM.CUSTOM_FIELDS_TO_ID): # pass by reference
    # Find the key for each of the corresponding field's name
    map_id_to_fields(meta_fields_dict, custom_fields_id_dict)


def map_id_to_fields(meta_fields_dict, fields_to_populate_id):
    for field in fields_to_populate_id:
        for meta_field in meta_fields_dict:
            if meta_fields_dict[meta_field]['name'] == field:
                fields_to_populate_id[field] = meta_fields_dict[meta_field]['key']

def get_reporter_account_id(email_address):
    json_data = JIRA_CLIENT.search_users_by_email(email_address)

    return json_data[0]['accountId']

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

#* Calculate a message digest for issue
def calc_issue_digest(summary, description, cve_id, component):
    hash = hashlib.sha256()
    overall_str = (summary + str(description) + cve_id + component).encode('utf-8')
    hash.update(overall_str)
    
    return hash.hexdigest()

# Potentially usable code in future
""" def populate_source_options_id(meta_fields_dict, field_source_options_id=CUSTOM.FIELD_SOURCE_OPTIONS_ID):
    # Get 'Source' field's key (customfield_...)
    Source_key = CUSTOM.CUSTOM_FIELDS_TO_ID['Source']

    # Find the id for each of the corresponding source field options
    for key in field_source_options_id:
        if key in meta_fields_dict[Source_key]['allowedValues']:
            continue # skip if field is not currently added/supported to 'Source' in Jira software
        for option in meta_fields_dict[Source_key]['allowedValues']:
            if key == option['value']:
                field_source_options_id[key] = option['id']

def populate_raw_sev_options_id(meta_fields_dict, field_sev_options_id=CUSTOM.FIELD_RAW_SEVERITY_OPTIONS_ID):
    pass

def populate_components_options_id():
    #todo
    pass """

#! Testing only
if __name__ == "__main__":
    init_all_fields_id("VULN")
    print(CUSTOM.CUSTOM_FIELDS_TO_ID)
    print(CUSTOM.FIELD_SOURCE_OPTIONS_ID)

    # Get all issues
    """ 
    query = ""
    all_issues_list = JIRA_CLIENT.jql_search_issues('project="VULN" AND status != "Closed"')
    print(all_issues_list)
    print("length of all_issue_list:", len(all_issues_list)) """

    # Test
    project_id = JIRA_CLIENT.search_project_id("vuln")
    vuln = JIRA_MODEL.Vuln(project_id='10001', summary='DS002_Misconfiguration', description=[{'type': 'text', 'text': 'Running containers with &#39;root&#39; user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a &#39;USER&#39; statement to the Dockerfile.'}, {'type': 'text', 'text': '\n\n'}, {'type': 'text', 'text': 'Artifact: Dockerfile\nType: dockerfile\nVulnerability DS002\nSeverity: HIGH\nMessage: Specify at least 1 USER command in Dockerfile with non-root user as argument\nLink: [DS002](https://avd.aquasec.com/misconfig/ds002)'}, {'type': 'text', 'text': '\n\n'}, {'type': 'text', 'text': 'Affected component: \nDockerfile (from Line: 1 to 1)\n'}], reporter_id='5b2f82cc55b2312db2b866e6', source='Trivy', cve_id='DS002', raw_severity='High', reported_date='2022-11-03', component='App A', issue_digest="cd4047db6316da4f66dcbaa5f546796bcdf9bf063b41f45c174a3047d8df003d")

    print("is_duplicate_finding():", is_duplicate_finding(vuln))
    