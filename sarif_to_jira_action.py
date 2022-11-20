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

#* Main
def main():
    # 1. Parse Input(s)
    parser = argparse.ArgumentParser(description='Create Jira tickets from Sarif files.')
    parser.add_argument('-f', '--filename', dest="sarif_filepath", action="store", help="Location and filename of the Sarif file.")
    parser.add_argument('-r', '--reporter-email', dest="jira_reporter_email", action="store", help="Jira user's email as ticket reporter")
    parser.add_argument('-c', '--affected-component', dest="affected_component", action="store", help="Affected component")
    parser.add_argument('-s', '--finding-source', dest="finding_source", action="store", help="Source of findings (e.g. trivySCA or codacySAST)")

    args = parser.parse_args()

    # 2. Execute the workflow
    workflow(args.sarif_filepath, args.affected_component, args.finding_source, args.jira_reporter_email)

#* The Workflow
def workflow(sarif_filepath, affected_component, finding_source, reporter_email):
    # 0. Verification(s)
    # Check if finding_source is in camelCase format
    if not JIRA_VULN.is_camel_case(finding_source):
        print("[!] Fatal error. The argument -s (--finding-source) is not in camelCase format. Please ensure this is fulfilled to prevent JQL search discrepancies. Please use the following format: aScanner or someScannerTool. For more information, please peruse the 'README.MD'.")
        return -1

    # 1. Retrieve and store Sarif file contents to dict format
    with open(sarif_filepath, 'r') as json_file:
        sarif_data = json.load(json_file)
    
    # 2. Extract VULN Jira ticket required information
    vuln_list = []
    for run in sarif_data['runs']:
        for result in run['results']:
            # Check: Skip if there are no results
            if not run['results']:
                continue 
            # 0. Define supported data extract style
            supported_style_one = ['Spotbugs (reported by Codacy)']
            supported_style_two = ['Trivy']

            # 1. Spotbugs(Codacy) style - No rules
            if run['tool']['driver']['name'] in supported_style_one:
                print("[*] Using Style One {SUPPORTED_STYLE} data extraction method".format(SUPPORTED_STYLE=str(supported_style_one)))
                this_rule = get_rule(run, result['ruleId'])
                summary = this_rule['name']
                description = get_description_dict_list([
                    result['message']['text'],
                    this_rule['help']['markdown'],
                    "Impacted artifact(s): \n" + get_affected_location_lines(result['locations'])
                ])                
                #Codacy-style severity
                cve_id = result['ruleId']
                raw_severity = codacy_level_to_severity(result[''])

            # 2.  Trivy style 
            elif run['tool']['driver']['name'] in supported_style_two:
                print("[*] Using Style Two {SUPPORTED_STYLE} data extraction method".format(SUPPORTED_STYLE=str(supported_style_two)))
                this_rule = get_rule(run, result['ruleId'])
                summary = this_rule['shortDescription']['text']
                description = get_description_dict_list([
                    this_rule['fullDescription']['text'], 
                    this_rule['help']['text'],
                    result['message']['text'],
                    "Impacted artifact(s): \n" + get_affected_location_lines(result['locations'])
                    ])
                cve_id = this_rule['id']
                raw_severity = JIRA_VULN.severity_num_to_qualitative(float(this_rule['properties']['security-severity']))
                first_reported_date = JIRA_VULN.get_current_date() # Default is GMT +8 "Asia/Singapore"
                last_reported_date = JIRA_VULN.get_current_date()
                issue_digest = JIRA_VULN.calc_issue_digest(summary, description, cve_id, affected_component)

                # Create a Vuln object and add to the reporting list
                vuln = JIRA_VULN.create_vuln(summary, description, reporter_email, finding_source, cve_id, raw_severity, first_reported_date, last_reported_date, affected_component, issue_digest)
                vuln_list.append(vuln)

    # 3. Report vulns
    JIRA_VULN.report_vuln_list(vuln_list, affected_component, finding_source)  


#? Helper functions
#? Process a list of description paragraphs into a proper Atlassian content list of dict 
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

#? Process a list of affected locations into lines
def get_affected_location_lines(location_list):
    affected_locations = ""
    for location in location_list:
        affected_locations += location['physicalLocation']['artifactLocation']['uri'] + " "
        affected_locations += "(from Line: {AFFECTED_START} to {AFFECTED_END})".format(AFFECTED_START=location['physicalLocation']['region']['startLine'], AFFECTED_END=location['physicalLocation']['region']['endLine']) + "\n"

    return affected_locations

#? Obtain the rule based on ruleId
def get_rule(run_data, rule_id):
    # If rules[] is empty
    if not run_data['tool']['driver']['rules']:
        return None
    for rule in run_data['tool']['driver']['rules']:
        if rule_id == rule['id']:
            return rule

#? Translate Codacy level to Severity level
def codacy_level_to_severity(text):
    if text == '':
        return 'Critical'
    elif text == 'warning':
        return 'Medium'
    else:
        return 'Low'


#! for testing only
if __name__ == "__main__":
    main()
