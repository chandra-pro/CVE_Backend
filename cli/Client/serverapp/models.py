"""
====================
models.py
Tables for CVE and CPEMatch response
author: Chandramani kumar, Shubham
===================

"""

from django.db import models
from django.utils import timezone
from uuid import uuid4

class CVE(models.Model):
    id = models.CharField(max_length=50, primary_key=True)
    source_identifier = models.CharField(max_length=100)
    published = models.DateTimeField(default=timezone.now)
    last_modified = models.DateTimeField(default=timezone.now)
    vuln_status = models.CharField(max_length=50)
    
    # Optional fields
    evaluator_comment = models.TextField(blank=True, null=True)
    evaluator_impact = models.TextField(blank=True, null=True)
    evaluator_solution = models.TextField(blank=True, null=True)
    cisa_exploit_add = models.DateField(blank=True, null=True)
    cisa_action_due = models.DateField(blank=True, null=True)
    cisa_required_action = models.TextField(blank=True, null=True)
    cisa_vulnerability_name = models.CharField(max_length=200, blank=True, null=True)

class CVETag(models.Model):
    cve = models.ForeignKey(CVE, related_name='cve_tags', on_delete=models.CASCADE)
    source = models.CharField(max_length=100)
    tag = models.CharField(max_length=50)

    class Meta:
        unique_together = ('cve', 'source', 'tag')

class CVEDescription(models.Model):
    cve = models.ForeignKey(CVE, related_name='descriptions', on_delete=models.CASCADE)
    lang = models.CharField(max_length=10)
    value = models.TextField()

    class Meta:
        unique_together = ('cve', 'lang')

class CVSSMetricV2(models.Model):
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE)
    source = models.CharField(max_length=255, blank=True, null=True)
    type = models.CharField(max_length=50, blank=True, null=True)
    version = models.CharField(max_length=10, blank=True, null=True)
    vector_string = models.TextField(blank=True, null=True)
    access_vector = models.CharField(max_length=50, blank=True, null=True)
    access_complexity = models.CharField(max_length=50, blank=True, null=True)
    authentication = models.CharField(max_length=50, blank=True, null=True)
    confidentiality_impact = models.CharField(max_length=50, blank=True, null=True)
    integrity_impact = models.CharField(max_length=50, blank=True, null=True)
    availability_impact = models.CharField(max_length=50, blank=True, null=True)
    base_score = models.FloatField(blank=True, null=True)
    base_severity = models.CharField(max_length=50, blank=True, null=True)
    exploitability_score = models.FloatField(blank=True, null=True)
    impact_score = models.FloatField(blank=True, null=True)
    ac_insuf_info = models.BooleanField(default=False)
    obtain_all_privilege = models.BooleanField(default=False)
    obtain_user_privilege = models.BooleanField(default=False)
    obtain_other_privilege = models.BooleanField(default=False)
    user_interaction_required = models.BooleanField(default=False)
 
 
class CVSSMetricV31(models.Model):
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE)  # Adjust length as needed
    source = models.CharField(max_length=255, blank=True, null=True)
    type = models.CharField(max_length=255, blank=True, null=True)
    version = models.CharField(max_length=10, blank=True, null=True)  # e.g., '3.1'
    vector_string = models.TextField(blank=True, null=True)  # Vector string might be lengthy

    attack_vector = models.CharField(max_length=50, blank=True, null=True)
    attack_complexity = models.CharField(max_length=50, blank=True, null=True)
    privileges_required = models.CharField(max_length=50, blank=True, null=True)
    user_interaction = models.CharField(max_length=50, blank=True, null=True)
    scope = models.CharField(max_length=50, blank=True, null=True)
    
    access_vector = models.CharField(max_length=50, blank=True, null=True)
    access_complexity = models.CharField(max_length=50, blank=True, null=True)
    authentication = models.CharField(max_length=50, blank=True, null=True)
    confidentiality_impact = models.CharField(max_length=50, blank=True, null=True)
    integrity_impact = models.CharField(max_length=50, blank=True, null=True)
    availability_impact = models.CharField(max_length=50, blank=True,null=True)
    base_score = models.FloatField(null=True, blank=True)  # Base score is a float
    base_severity = models.CharField(max_length=50, blank=True)  # Severity level as string
    exploitability_score = models.FloatField(null=True, blank=True)  # Exploitability score
    impact_score = models.FloatField(null=True, blank=True)  # Impact score

class CVEWeakness(models.Model):
    cve = models.ForeignKey(CVE, related_name='weaknesses', on_delete=models.CASCADE)
    source = models.CharField(max_length=100)
    type = models.CharField(max_length=50)
    description = models.TextField()

class CVEConfiguration(models.Model):
    cve = models.ForeignKey(CVE, related_name='configurations', on_delete=models.CASCADE)
    operator = models.CharField(max_length=10)
    negate = models.BooleanField()

class CPEMatch(models.Model):
    configuration = models.ForeignKey(CVEConfiguration, related_name='cpe_matches', on_delete=models.CASCADE)
    vulnerable = models.BooleanField()
    criteria = models.CharField(max_length=200)
    match_criteria_id = models.UUIDField(default=uuid4, editable=False)
    version_start_including = models.CharField(max_length=50, blank=True, null=True)
    version_end_including = models.CharField(max_length=50, blank=True, null=True)
    version_start_excluding = models.CharField(max_length=50, blank=True, null=True)
    version_end_excluding = models.CharField(max_length=50, blank=True, null=True)

class CVEReference(models.Model):
    cve = models.ForeignKey(CVE, related_name='references', on_delete=models.CASCADE)
    url = models.URLField()
    source = models.CharField(max_length=100)
    tags = models.JSONField(blank=True, null=True)  # Using built-in JSONField

class CVENode(models.Model):
    configuration = models.ForeignKey(CVEConfiguration, related_name='nodes', on_delete=models.CASCADE)
    operator = models.CharField(max_length=10)
    negate = models.BooleanField()

class CPEMatchInNode(models.Model):
    node = models.ForeignKey(CVENode, related_name='cpe_matches', on_delete=models.CASCADE)
    vulnerable = models.BooleanField()
    criteria = models.CharField(max_length=200)
    match_criteria_id = models.UUIDField(default=uuid4, editable=False)
    version_start_including = models.CharField(max_length=50, blank=True, null=True)
    version_end_including = models.CharField(max_length=50, blank=True, null=True)
    version_start_excluding = models.CharField(max_length=50, blank=True, null=True)
    version_end_excluding = models.CharField(max_length=50, blank=True, null=True)

class MatchString(models.Model):
    match_criteria_id = models.UUIDField(default=uuid4, editable=False, unique=True)
    criteria = models.CharField(max_length=255)
    last_modified = models.DateTimeField(default=timezone.now, null=True, blank=True)
    cpe_last_modified = models.DateTimeField(default=timezone.now, null=True, blank=True)
    created = models.DateTimeField(default=timezone.now, null=True, blank=True)
    status = models.CharField(max_length=50)  # choices=[('Active', 'Active'), ('Inactive', 'Inactive')])

    # Optional fields
    version_start_including = models.CharField(max_length=50, blank=True, null=True)
    version_end_including = models.CharField(max_length=50, blank=True, null=True)
    version_start_excluding = models.CharField(max_length=50, blank=True, null=True)
    version_end_excluding = models.CharField(max_length=50, blank=True, null=True)

    # JSON field to store matches
    matches = models.JSONField(default=list, blank=True)  # stores an array of {cpe_name, cpe_name_id} objects

    def __str__(self):
        return self.criteria

class MatchStringSyncLog(models.Model):
    last_sync = models.DateTimeField()
    status = models.CharField(max_length=255)
    message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
 
    def __str__(self):
        return f"MatchString Sync Log: {self.last_sync} - {self.status}"
    
from django.db import models
from django.utils import timezone

class CVESyncLog(models.Model):
    last_sync = models.DateTimeField()
    status = models.CharField(max_length=50)
    message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)