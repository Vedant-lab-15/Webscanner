from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from django.contrib import messages
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.db.models import Count

import json
import logging
import threading
from urllib.parse import urlparse

from .models import ScanReport, VulnerabilityType, Vulnerability
from .utils.scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)

# Initialize the scanner
scanner = VulnerabilityScanner()

def index(request):
    """Home page with introduction to the scanner."""
    return render(request, 'scanner/index.html', {
        'title': 'Web Vulnerability Scanner',
    })

def dashboard(request):
    """Dashboard showing recent scans and vulnerability statistics."""
    # Get recent reports
    recent_reports = ScanReport.objects.all()[:10]
    
    # Get vulnerability statistics
    vulnerability_stats = Vulnerability.objects.values('vulnerability_type__name', 'vulnerability_type__severity') \
                            .annotate(count=Count('id')) \
                            .order_by('-count')
    
    # Count by severity
    severity_counts = {}
    for stat in vulnerability_stats:
        severity = stat['vulnerability_type__severity']
        if severity not in severity_counts:
            severity_counts[severity] = 0
        severity_counts[severity] += stat['count']
    
    # Get vulnerability types for scan form
    vulnerability_types = VulnerabilityType.objects.all()
    
    context = {
        'title': 'Security Dashboard',
        'recent_reports': recent_reports,
        'vulnerability_stats': vulnerability_stats,
        'severity_counts': severity_counts,
        'vulnerability_types': vulnerability_types,
    }
    return render(request, 'scanner/dashboard.html', context)

def scan_form(request):
    """Display the form for submitting a URL or code snippet for scanning."""
    return render(request, 'scanner/scan.html', {
        'title': 'Scan for Vulnerabilities',
    })

def run_scan(report_id, url=None, snippet=None):
    """Run the scan in a separate thread and update the database with results."""
    try:
        # Get the report
        report = ScanReport.objects.get(id=report_id)
        report.status = 'IN_PROGRESS'
        report.save()
        
        # Initialize vulnerability types if they don't exist
        vulnerability_types = {
            'xss': VulnerabilityType.objects.get_or_create(
                name='Cross-Site Scripting (XSS)',
                defaults={
                    'description': 'Allows attackers to inject client-side scripts into web pages viewed by other users',
                    'severity': 'HIGH'
                }
            )[0],
            'sqli': VulnerabilityType.objects.get_or_create(
                name='SQL Injection',
                defaults={
                    'description': 'Allows attackers to execute malicious SQL statements to control a database server',
                    'severity': 'CRITICAL'
                }
            )[0],
            'csrf': VulnerabilityType.objects.get_or_create(
                name='Cross-Site Request Forgery (CSRF)',
                defaults={
                    'description': 'Forces end users to execute unwanted actions on a web application in which they are authenticated',
                    'severity': 'MEDIUM'
                }
            )[0],
            'sensitive_data': VulnerabilityType.objects.get_or_create(
                name='Sensitive Data Exposure',
                defaults={
                    'description': 'Exposure of sensitive information like credit cards, IDs, credentials, etc.',
                    'severity': 'HIGH'
                }
            )[0]
        }
        
        # Run the scan
        if url:
            scan_results = scanner.scan_url(url)
        else:
            scan_results = scanner.scan_snippet(snippet)
        
        # Process results and save vulnerabilities
        if scan_results['status'] == 'completed':
            # Save vulnerabilities
            for vuln_type, vulnerabilities in scan_results.items():
                if vuln_type in ['xss', 'sqli', 'csrf', 'sensitive_data'] and vulnerabilities:
                    for vuln in vulnerabilities:
                        Vulnerability.objects.create(
                            report=report,
                            vulnerability_type=vulnerability_types[vuln_type],
                            line_number=vuln.get('line_number'),
                            column=vuln.get('column'),
                            payload=vuln.get('match', ''),
                            context=vuln.get('context', ''),
                            description=f"Found {vuln_type.upper()} vulnerability in line {vuln.get('line_number')}",
                            remediation_advice=scanner.generate_remediation_advice(vuln_type, vuln.get('match', ''))
                        )
            
            report.status = 'COMPLETED'
        else:
            report.status = 'FAILED'
            # Create an error vulnerability to store the error message
            Vulnerability.objects.create(
                report=report,
                vulnerability_type=vulnerability_types['sensitive_data'],  # Using as a generic type
                payload='Error during scan',
                context=scan_results.get('error', 'Unknown error occurred'),
                description='Error during vulnerability scan',
                remediation_advice='Please check the URL or code snippet and try again.'
            )
            
        report.save()
        
    except Exception as e:
        logger.exception(f"Error during scan for report {report_id}")
        try:
            report = ScanReport.objects.get(id=report_id)
            report.status = 'FAILED'
            report.save()
        except:
            pass

@require_http_methods(["POST"])
def submit_scan(request):
    """Handle form submission and start a scan."""
    try:
        url = request.POST.get('url', '').strip()
        snippet = request.POST.get('code_snippet', '').strip()
        
        # Validate inputs
        if not url and not snippet:
            messages.error(request, "Please provide either a URL or a code snippet.")
            return redirect('scanner:scan_form')
            
        # Create scan report
        report = ScanReport()
        if url:
            # Basic URL validation
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                messages.error(request, "Invalid URL format. URL must include scheme (http:// or https://).")
                return redirect('scanner:scan_form')
                
            report.url = url
        else:
            report.snippet = snippet
            
        report.save()
        
        # Start the scan in a separate thread
        thread = threading.Thread(
            target=run_scan,
            args=(report.id, url, snippet)
        )
        thread.daemon = True
        thread.start()
        
        # Redirect to results page
        return redirect('scanner:report_detail', report_id=report.id)
        
    except Exception as e:
        logger.exception("Error submitting scan")
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('scanner:scan_form')

def reports_list(request):
    """List all scan reports."""
    reports = ScanReport.objects.all().order_by('-scan_date')
    return render(request, 'scanner/reports_list.html', {
        'title': 'Scan Reports',
        'reports': reports
    })

def report_detail(request, report_id):
    """Show detailed results of a specific scan."""
    report = get_object_or_404(ScanReport, id=report_id)
    vulnerabilities = report.vulnerabilities.all().select_related('vulnerability_type')
    
    # Group vulnerabilities by type
    vulnerabilities_by_type = {}
    for vuln in vulnerabilities:
        vuln_type = vuln.vulnerability_type.name
        if vuln_type not in vulnerabilities_by_type:
            vulnerabilities_by_type[vuln_type] = []
        vulnerabilities_by_type[vuln_type].append(vuln)
    
    return render(request, 'scanner/report_detail.html', {
        'title': f'Scan Report #{report.id}',
        'report': report,
        'vulnerabilities': vulnerabilities,
        'vulnerabilities_by_type': vulnerabilities_by_type
    })

def delete_report(request, report_id):
    """Delete a scan report."""
    report = get_object_or_404(ScanReport, id=report_id)
    report.delete()
    messages.success(request, "Report deleted successfully.")
    return redirect('scanner:reports_list')

def scan_status(request, report_id):
    """API endpoint to check the status of a scan."""
    try:
        report = get_object_or_404(ScanReport, id=report_id)
        vuln_count = report.vulnerabilities.count()
        
        return JsonResponse({
            'status': report.status,
            'vulnerability_count': vuln_count
        })
    except Exception as e:
        return JsonResponse({
            'status': 'ERROR',
            'message': str(e)
        }, status=500)