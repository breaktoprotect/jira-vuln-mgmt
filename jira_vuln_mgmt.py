"""
Author  : Jeremy S. (@breaktoprotect)
Date    : 22 Oct 2022
Description:
- Logic for implementing vulnerability ticket creation via Jira
"""
#import here

import jira_client as JIRA
import custom_fields as CUSTOM


#? Config
PROJECT_KEY = "VULN" #e.g. VULN-123 on Jira

#? Helper functions
def populate_custom_fields_id(custom_fields_id_dict=CUSTOM.CUSTOM_FIELDS_TO_ID): # by reference
    metadata_dict = JIRA.get_metadata_create_issue(PROJECT_KEY)
    fields_dict = metadata_dict['projects'][0]['issuetypes']

    # Get the dict of metadata fields
    for issuetype in metadata_dict['projects'][0]['issuetypes']:
        meta_fields_dict = issuetype['fields']

    # Find the key for each of the corresponding field's name
    for cust_field in custom_fields_id_dict:
        for meta_field in meta_fields_dict:
            if meta_fields_dict[meta_field]['name'] == cust_field:
                custom_fields_id_dict[cust_field] = meta_fields_dict[meta_field]['key']

#! Testing only
if __name__ == "__main__":
    populate_custom_fields_id()

    print(CUSTOM.CUSTOM_FIELDS_TO_ID)