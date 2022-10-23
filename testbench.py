"""
Just a test bench for testing during development
"""
from jira_client import *
from jira_vuln_mgmt import *

def _create_vuln_jira_issue():
    # 1. Init
    init_all_fields_id("VULN")

    #debug
    print(CUSTOM.CUSTOM_FIELDS_TO_ID)
    print(CUSTOM.FIELD_SOURCE_OPTIONS_ID)

    # 2. Setup
    vuln = MODEL.Vuln(
        summary="A test summary", 
        project_id=search_project_id("VuLN"),  
        description="test description",
        reporter="5b2f82cc55b2312db2b866e6",
        source="SCA",
        cve_id="CVE-1234-12345678",
        raw_severity="Medium",
        #assessed_severity=None,
        #status_expiry="01/10/2022",
        reported_date="2022-10-22",
        component="App A"
        )

    print(create_jira_vuln(vuln))

if __name__ == "__main__":
    _create_vuln_jira_issue()