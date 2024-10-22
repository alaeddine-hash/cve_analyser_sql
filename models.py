# models.py

from typing import List, Optional, Dict
from pydantic import BaseModel

class ExploitabilityMetric(BaseModel):
    value: Optional[str]
    assessment: Optional[str]
    remarks: Optional[str]

class ExploitationContext(BaseModel):
    general_explanation: Optional[str]
    contexts: Optional[List[Dict]]

class Patch(BaseModel):
    release_link: Optional[str]
    last_update: Optional[str]
    recommendations: Optional[str]

class CVEEntry(BaseModel):
    cve_id: str
    os_name: Optional[List[str]] = []
    os_version: Optional[List[str]] = []
    description: Optional[str] = ''
    cvss_score_v3: Optional[str] = ''
    cvss_vector_v3: Optional[str] = ''
    weaknesses: Optional[List[str]] = []
    configurations: Optional[List[str]] = []
    references: Optional[List[Dict]] = []
    exploitation_context: Optional[ExploitationContext]
    Side: Optional[str] = ''
    exploitability_metrics: Optional[Dict[str, ExploitabilityMetric]] = {}
    overall_assessment: Optional[str] = ''
    remarks: Optional[str] = ''
    patch_available: Optional[bool] = False
    patch: Optional[Patch]
    mitigation_measures: Optional[Dict] = {}
