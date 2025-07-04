from django.db import models
from django.utils import timezone

class VulnerabilityType(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    severity_choices = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    severity = models.CharField(max_length=10, choices=severity_choices, default='MEDIUM')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_severity_display()})"

class ScanReport(models.Model):
    url = models.URLField(max_length=500, blank=True, null=True)
    snippet = models.TextField(blank=True, null=True)
    scan_date = models.DateTimeField(default=timezone.now)
    status_choices = [
        ('PENDING', 'Pending'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    status = models.CharField(max_length=15, choices=status_choices, default='PENDING')
    
    def __str__(self):
        return f"Scan {self.id}: {self.url if self.url else 'Code Snippet'} - {self.status}"
    
    class Meta:
        ordering = ['-scan_date']

class Vulnerability(models.Model):
    report = models.ForeignKey(ScanReport, on_delete=models.CASCADE, related_name='vulnerabilities')
    vulnerability_type = models.ForeignKey(VulnerabilityType, on_delete=models.CASCADE)
    line_number = models.IntegerField(null=True, blank=True)
    column = models.IntegerField(null=True, blank=True)
    payload = models.TextField()
    context = models.TextField(help_text="Code context where vulnerability was found")
    description = models.TextField()
    remediation_advice = models.TextField()
    
    def __str__(self):
        return f"{self.vulnerability_type.name} in {self.report}"