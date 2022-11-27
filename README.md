# jira-vuln-mgmt
A setup to manage vulnerabilities on Jira and allow automation of creation and closing of Jira tickets based on scan reports.

# Requirements
## Setting up 
### Issue Type
Must have:
- 1 issue type name "Vulnerability" for creation of Jira issues.

### Status requirements
Must have:
- Open
- Auto Closed (Custom)

# Notes and Limitations
## JQL Text search
As JQL doesn't support exact match for short text fields (e.g. Finding Source is one of them), do not use similar 'Finding Source' names. For example, if you have the following 'Finding Source' 'Trivy' and 'Trivy-SCA', when the 'Trivy' triggers, it will affect 'Trivy-SCA' issues also. You have been warned! 

### Advice
Use 'Finding Source':
- 'SomeScanner' 

Avoid: 
- 'Some Scanner'
- 'Some_Scanner'
- 'Some-Scanner'

## New 'old' findings
If an issue has been 'Closed' or 'Auto Closed', and the finding with the same digest exist, the existing 'Closed' or 'Auto Closed' will be re-opened up.

## Custom VULN format
The Jira reporting tool supports a custom file format known as the VULN JSON or vJSON in short. The expected file format is:
```
{
    "format": "vjson",
    "results": [
        {
            "summary": "PATH_TRAVERSAL_IN - This API (java/io/File.<init>(...",
            "description": [
                "This API (java/io/File.<init>(Ljava/lang/String;)V) reads a file whose location might be specified by user input\n",
                "A file is opened to read its content. The filename comes from an input parameter.\nIf an unfiltered parameter is passed to this file API, files from an arbitrary filesystem location could be read.This rule identifies potential path traversal vulnerabilities. In many cases, the constructed file path cannot be controlled\nby the user. If that is the case, the reported instance is a false positive.\nFor further information, please visit https://find-sec-bugs.github.io/bugs.htm#PATH_TRAVERSAL_IN\n",
                "Affected artifact(s):\nsrc/main/java/com/org_name/module/config/SomeConfig.java -             sslConfig = sslConfig.pemFile(new File(somePath)); (Line: 84)"
            ],
            "cve_id": "PATH_TRAVERSAL_IN",
            "raw_severity": "Critical"
        },
        {
            ...
        }
    ]
}
```