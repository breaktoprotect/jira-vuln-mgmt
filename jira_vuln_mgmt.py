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

#? ***** Helper functions *****
#* Prepare any required information such as field keys, options for each fields, etc. 
#  This is to avoid hardcoding specific field keys (e.g. hardcoding customfield_10011 for 'Reported Date' field)
def init_all_fields_id(PROJECT_KEY):
    # Get the dict of metadata fields
    metadata_dict = JIRA.get_metadata_create_issue(PROJECT_KEY)

    for issuetype in metadata_dict['projects'][0]['issuetypes']:
        meta_fields_dict = issuetype['fields']

    # 1. Populate fields key 
    populate_custom_fields_key(meta_fields_dict)

    # 2. Populate field 'source' options id
    #populate_source_options_id(meta_fields_dict)

def populate_custom_fields_key(meta_fields_dict, custom_fields_id_dict=CUSTOM.CUSTOM_FIELDS_TO_ID): # pass by reference
    # Find the key for each of the corresponding field's name
    map_id_to_fields(meta_fields_dict, custom_fields_id_dict)


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

    
def map_id_to_fields(meta_fields_dict, fields_to_populate_id):
    for field in fields_to_populate_id:
        for meta_field in meta_fields_dict:
            if meta_fields_dict[meta_field]['name'] == field:
                fields_to_populate_id[field] = meta_fields_dict[meta_field]['key']

#! Testing only
if __name__ == "__main__":
    init_all_fields_id("VULN")

    print(CUSTOM.CUSTOM_FIELDS_TO_ID)
    print(CUSTOM.FIELD_SOURCE_OPTIONS_ID)