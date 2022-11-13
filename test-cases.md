# Test Cases to run
## 1. Empty Vuln List with Empty Jira List of an affected_component from a finding_source
Test Param(s):
- test_cases/trivy-dockerfile-config_clean.sarif
- JQL of affected_component and finding_source should return 0 

Expected outcome:
- Jira-Vuln-Mgmt will exit with following msg: 
```
[*] No vulnerabilities to report. There are also no existing issues to auto close. Operation exited.
```

## 2. Initial Vuln List of Findings
Test Param(s):
- test_cases/trivy-dockerfile-config.sarif

Expected outcome:
- All findings will be populated in the Jira 

## 3. Partial Fixed - Auto Close some issues
Test Param(s):
- test_cases/trivy-dockerfile-config_fixed.sarif

Expected outcome:
- A few findings are marked as AUTO CLOSED

## 4. Empty Vuln List with existing Jira Issues List (at least one)
Test Param(s):
- Manually set one Jira issue to 'CLOSED'
- test_cases/trivy-dockerfile-config_clean.sarif
- JQL of affected_component and finding_source should return at least 1

Expected outcome:
- JQL of affected_component and finding_source issues will all set to AUTO CLOSED.
- Issue that are already CLOSED, will not be marked AUTO CLOSED.