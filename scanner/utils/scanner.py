"""
Core vulnerability scanner implementation for the WebScanner project.
This module contains the logic for detecting XSS, SQL Injection, and other
common web vulnerabilities using pattern matching and analysis techniques.
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """
    Main scanner class that detects various web vulnerabilities.
    """
    
    def __init__(self):
        self.xss_patterns = [
            r'<script>.*?</script>',                         # Basic script tags
            r'javascript:.*?\(.*?\)',                         # JavaScript protocol
            r'on\w+\s*=\s*["\']\s*.*?\s*["\']',              # Event handlers
            r'<\s*img[^>]*src\s*=\s*["\']?[^"\']*?onerror', # Image onerror
            r'<\s*iframe[^>]*src\s*=\s*["\']?javascript:',   # Iframe with js
            r'<\s*svg[^>]*onload\s*=\s*["\']?',              # SVG onload
            r'eval\s*\(',                                     # eval()
            r'document\.cookie',                              # Cookie access
            r'document\.location',                            # Location manipulation
        ]
        
        self.sqli_patterns = [
            r'\b(select|union|insert|update|delete|drop|alter)\b.*?\bfrom\b',  # Basic SQL keywords
            r'--',                                                             # SQL comment
            r'/\*.*?\*/',                                                      # SQL block comment
            r"['\"]\s*(\s*(or|OR)\s+.*(=|>|<))",                              # OR-based injection
            r"['\"]\s*(\s*(and|AND)\s+.*(=|>|<))",                            # AND-based injection
            r'1\s*=\s*1',                                                      # Always true
            r"'\s+or\s+'1'\s*=\s*'1",                                         # String OR injection
            r"admin['\"]\s*--",                                               # Admin bypass
        ]

        self.csrf_patterns = [
            r'<form[^>]*method=["\']post["\'][^>]*>(?:(?!csrf|token).)*?</form>', # Forms without CSRF protection
        ]
        
        self.sensitive_data_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',  # Email
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',                         # IP Address
            r'\b(?:\d{4}[- ]?){3}\d{4}\b',                          # Credit Card
            r'\b(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b', # Base64
        ]
    
    def _find_pattern_matches(self, content, patterns):
        """Find matches for a list of regex patterns in the given content."""
        matches = []
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                matches.append({
                    'pattern': pattern,
                    'match': match.group(0),
                    'position': match.span(),
                    'line_number': content[:match.start()].count('\n') + 1,
                    'column': match.start() - content[:match.start()].rfind('\n') if '\n' in content[:match.start()] else match.start() + 1
                })
        return matches
    
    def get_context(self, content, match_position, context_lines=3):
        """Extract surrounding context of a vulnerability match."""
        start, end = match_position
        lines = content.splitlines()
        line_start = content[:start].count('\n')
        line_end = line_start + content[start:end].count('\n')
        
        # Get context lines before and after
        context_start = max(0, line_start - context_lines)
        context_end = min(len(lines), line_end + context_lines + 1)
        
        # Format the context with line numbers
        context = []
        for i in range(context_start, context_end):
            line_prefix = '> ' if context_start <= i <= line_end else '  '
            context.append(f"{line_prefix}{i+1}: {lines[i]}")
            
        return '\n'.join(context)
    
    def scan_url(self, url):
        """Scan a URL for vulnerabilities."""
        results = {
            'xss': [],
            'sqli': [],
            'csrf': [],
            'sensitive_data': [],
            'url': url,
            'status': 'completed'
        }
        
        try:
            # Validate URL format
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                results['status'] = 'failed'
                results['error'] = "Invalid URL format. URL must include scheme (http:// or https://)."
                return results

            # Make the request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            content = response.text
            
            # Extract forms and inputs for deeper analysis
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            
            # Scan HTML content
            results['xss'] = self._find_pattern_matches(content, self.xss_patterns)
            results['sqli'] = self._find_pattern_matches(content, self.sqli_patterns)
            results['csrf'] = self._find_pattern_matches(content, self.csrf_patterns)
            results['sensitive_data'] = self._find_pattern_matches(content, self.sensitive_data_patterns)
            
            # Add context to each vulnerability
            for category in ['xss', 'sqli', 'csrf', 'sensitive_data']:
                for vuln in results[category]:
                    vuln['context'] = self.get_context(content, vuln['position'])
            
            # Analyze forms
            for form in forms:
                form_html = str(form)
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Check form for vulnerabilities
                form_xss = self._find_pattern_matches(form_html, self.xss_patterns)
                form_sqli = self._find_pattern_matches(form_html, self.sqli_patterns)
                
                # Add form-specific context
                for vuln in form_xss:
                    vuln['form_action'] = form_action
                    vuln['form_method'] = form_method
                    vuln['context'] = self.get_context(content, vuln['position'])
                    results['xss'].append(vuln)
                
                for vuln in form_sqli:
                    vuln['form_action'] = form_action
                    vuln['form_method'] = form_method
                    vuln['context'] = self.get_context(content, vuln['position'])
                    results['sqli'].append(vuln)
                
                # Check for CSRF vulnerabilities specifically in forms
                if form_method == 'post':
                    csrf_token = False
                    for inp in form.find_all('input'):
                        if any(token_name in (inp.get('name', '') + inp.get('id', '')).lower() 
                                for token_name in ['csrf', 'token', '_token', 'xsrf']):
                            csrf_token = True
                            break
                    
                    if not csrf_token:
                        csrf_vuln = {
                            'pattern': 'Missing CSRF token',
                            'match': form_html[:50] + '...',  # Just show the beginning of the form
                            'position': (content.find(form_html), content.find(form_html) + len(form_html)),
                            'line_number': content[:content.find(form_html)].count('\n') + 1,
                            'column': content.find(form_html) - content[:content.find(form_html)].rfind('\n') if '\n' in content[:content.find(form_html)] else content.find(form_html) + 1,
                            'form_action': form_action,
                            'form_method': form_method,
                            'context': self.get_context(content, (content.find(form_html), content.find(form_html) + len(form_html)))
                        }
                        results['csrf'].append(csrf_vuln)
                        
        except requests.exceptions.RequestException as e:
            results['status'] = 'failed'
            results['error'] = f"Request failed: {str(e)}"
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = f"Error during scanning: {str(e)}"
            logger.exception(f"Error scanning URL {url}")
            
        return results
    
    def scan_snippet(self, code_snippet):
        """Scan a code snippet for vulnerabilities."""
        results = {
            'xss': [],
            'sqli': [],
            'csrf': [],
            'sensitive_data': [],
            'status': 'completed'
        }
        
        try:
            # Scan the code snippet
            results['xss'] = self._find_pattern_matches(code_snippet, self.xss_patterns)
            results['sqli'] = self._find_pattern_matches(code_snippet, self.sqli_patterns)
            results['csrf'] = self._find_pattern_matches(code_snippet, self.csrf_patterns)
            results['sensitive_data'] = self._find_pattern_matches(code_snippet, self.sensitive_data_patterns)
            
            # Add context to each vulnerability
            for category in ['xss', 'sqli', 'csrf', 'sensitive_data']:
                for vuln in results[category]:
                    vuln['context'] = self.get_context(code_snippet, vuln['position'])
                    
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = f"Error during scanning: {str(e)}"
            logger.exception("Error scanning code snippet")
            
        return results
    
    def generate_remediation_advice(self, vulnerability_type, match):
        """Generate remediation advice based on the vulnerability type and match content."""
        if vulnerability_type == 'xss':
            if '<script>' in match.lower():
                return ("Use Content-Security-Policy headers and sanitize user input. "
                        "Replace direct HTML embedding with safer alternatives like textContent "
                        "instead of innerHTML. Consider using frameworks that automatically escape output.")
            elif 'onerror' in match.lower():
                return ("Remove inline event handlers and use JavaScript addEventListener instead. "
                        "Always validate and sanitize user input before using it to create HTML elements.")
            else:
                return ("Sanitize all user input before rendering it in HTML context. "
                        "Consider using libraries like DOMPurify or frameworks with built-in XSS protection.")
                
        elif vulnerability_type == 'sqli':
            return ("Use parameterized queries or prepared statements instead of string concatenation. "
                    "Apply proper input validation and use ORM frameworks when possible. "
                    "Implement the principle of least privilege for database users.")
                    
        elif vulnerability_type == 'csrf':
            return ("Implement anti-CSRF tokens for all state-changing operations. "
                    "Use SameSite cookie attribute and verify the origin of requests. "
                    "Consider implementing the 'Double Submit Cookie' pattern.")
                    
        elif vulnerability_type == 'sensitive_data':
            return ("Avoid storing sensitive data in client-accessible code. "
                    "Use HTTPS for all data transmission. Consider data masking and "
                    "implement proper access controls for sensitive information.")
        
        return "Review this code for potential security issues and apply appropriate security controls."