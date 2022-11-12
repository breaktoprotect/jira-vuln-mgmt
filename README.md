# jira-vuln-mgmt
A setup to manage vulnerabilities on Jira and allow automation of creation and closing of Jira tickets based on scan reports.

# Limitations
## JQL Text search
As JQL doesn't support exact match for short text fields (e.g. Finding Source is one of them), do not use similar 'Finding Source' names. For example, if you have the following 'Finding Source' 'Trivy' and 'Trivy-SCA', when the 'Trivy' triggers, it will affect 'Trivy-SCA' issues also. You have been warned! 
### Advice
Use 'Finding Source':
- 'SomeScanner' 
Avoid: 
- 'Some Scanner'
- 'Some_Scanner'
- 'Some-Scanner'