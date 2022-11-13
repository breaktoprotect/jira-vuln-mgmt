#
#* Project Key (e.g. VULN in the 'VULN-128')
PROJECT_KEY = "VULN" # Best to keep it in caps

#* Custom fields
# To be retrieved dynamically from Jira Software (Cloud)
CUSTOM_FIELDS_TO_ID = {
    "First Reported Date": None,
    "Last Reported Date": None,
    "Raw Severity": None,
    "Assessed Severity": None,
    "CVE ID": None,
    "Finding Source": None,
    "Status Expiry": None,
    "Issue Digest": None,
    "Affected Component": None
}

FIELD_RAW_SEVERITY_OPTIONS_ID = {
    "Critical": None,
    "High": None,
    "Medium": None,
    "Low": None,
    "None (Informational)": None
}

FIELD_RAW_SEVERITY_OPTIONS_ID = {
    "Critical": None,
    "High": None,
    "Medium": None,
    "Low": None,
    "None (Informational)": None
}

#* ISSUE TYPE ID
ISSUE_TYPE_ID = None # Pleae note: has to be int, not String

#* Transition ID
TRANSITION_ID = None