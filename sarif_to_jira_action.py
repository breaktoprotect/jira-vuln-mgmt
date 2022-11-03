"""
Author  : Jeremy S. (@breaktoprotect)
Date    : 30 Oct 2022
Description:
- Creates/syncs Jira tickets out of any Sarif (Static Analysis Results Interchange Format - JSON-based) results from security scanners
"""
import argparse
import json
import jira_vuln_mgmt as JIRA_VULN
import datetime


#? Config
PROJECT_KEY = "vuln"

#* Main
def main():
    # 1. Parse Input(s)
    parser = argparse.ArgumentParser(description='Create Jira tickets from Sarif files.')
    parser.add_argument('-f', '--filename', dest="sarif_filepath", action="store", help="Location and filename of the Sarif file.")
    parser.add_argument('-r', '--reporter-email', dest="jira_reporter_email", action="store", help="Jira user's email as ticket reporter")
    parser.add_argument('-c', '--affected-component', dest="affected_component", action="store", help="Affected component")

    args = parser.parse_args()

    # 2. Execute the workflow
    workflow(args.sarif_filepath, args.affected_component, args.jira_reporter_email)

#* The Workflow
def workflow(sarif_filepath, component, reporter_email):
    # 1. Retrieve and store Sarif file contents to dict format
    with open(sarif_filepath, 'r') as json_file:
        sarif_data = json.load(json_file)
    
    # 2. Extract VULN Jira ticket required information
    vuln_list = []
    for run in sarif_data['runs']:
        driver = run['tool']['driver']
        for index, rule in enumerate(driver['rules']):
            summary = rule['id'] + "_" + rule['name']
            description = get_description_dict_list([
                rule['fullDescription']['text'], 
                run['results'][index]['message']['text'],
                "Affected component: \n" + get_affected_location_lines(run['results'][index]['locations'])
                ]) # Needs to be in paragraphs
            source = driver['name']
            cve_id = rule['id']
            raw_severity=JIRA_VULN.severity_num_to_qualitative(float(rule['properties']['security-severity']))
            reported_date = datetime.datetime.utcnow().strftime('%Y-%m-%d')
            issue_digest = JIRA_VULN.calc_issue_digest(summary, description, cve_id, component)

            vuln = JIRA_VULN.create_vuln(summary, PROJECT_KEY, description, reporter_email, source, cve_id, raw_severity, reported_date, component, issue_digest)
            vuln_list.append(vuln)

    # 3. Report vulns
    JIRA_VULN.report_vuln_list(vuln_list, PROJECT_KEY)

    """
    summary="A test summary", 
    project_key="VULN",  
    description="test description",
    reporter="5b2f82cc55b2312db2b866e6",
    source="SCA",
    cve_id="CVE-1234-12345678",
    raw_severity="Medium",
    reported_date="2022-10-22",
    component="App A"
    """
    

#? Helper functions
#* Process a list of description paragraphs into a proper Atlassian content list of dict 
def get_description_dict_list(description_list):
    content_dict_list = []
    for index, desc in enumerate(description_list):
        paragraph = {
            "type": "text",
            "text": desc
        }
        content_dict_list.append(paragraph)

        # Create a space (except last item)
        if not (index == (len(description_list) - 1)):
            content_dict_list.append(
                {
                    "type": "text",
                    "text": "\n\n"
                }
            )
    
    return content_dict_list

#* Process a list of affected locations into lines
def get_affected_location_lines(location_list):
    affected_locations = ""
    for location in location_list:
        affected_locations += location['physicalLocation']['artifactLocation']['uri'] + " "
        affected_locations += "(from Line: {AFFECTED_START} to {AFFECTED_END})".format(AFFECTED_START=location['physicalLocation']['region']['startLine'], AFFECTED_END=location['physicalLocation']['region']['endLine']) + "\n"

    return affected_locations



#! for testing only
if __name__ == "__main__":
    main()
