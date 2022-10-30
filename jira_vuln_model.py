"""
Author  : Jeremy S. @breaktoprotect
Date    : 22 Oct 2022
Description:
- Provide data model for vuln Jira submission
"""

from dataclasses import dataclass


@dataclass
class Vuln(object):
    project_id: int
    summary: str
    description: str
    reporter_id: str
    source: str
    cve_id: str
    raw_severity: str
    #assessed_severity: str - this is not a generated field. Requires human intervention (and maybe ML in future)
    #status_expiry: str - this is not a generated field. Only used for False Positive or Risk Acceptance tracking
    reported_date: str # Must be "yyyy-MM-dd"
    component: str

    