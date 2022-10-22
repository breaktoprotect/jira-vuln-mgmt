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
    reporter: int
    
    