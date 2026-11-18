"""
SSLGuard Reports
Generates CSV and PDF remediation reports.
"""

import csv
import io
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from models import Domain, Scan


class ReportGenerator:
    """Generates remediation reports in CSV and PDF formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
    
    def generate_csv_report(self):
        """Generate CSV remediation report for all domains"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Domain',
            'Port',
            'Owner',
            'Issue',
            'Status',
            'Recommended Action'
        ])
        
        # Get all domains with their latest scans
        domains = Domain.query.all()
        
        for domain in domains:
            latest_scan = domain.get_latest_scan()
            
            if not latest_scan:
                # No scan data
                writer.writerow([
                    domain.hostname,
                    domain.port,
                    domain.owner,
                    'No scan data',
                    'Unknown',
                    'Run a scan first'
                ])
                continue
            
            if latest_scan.error:
                # Scan failed
                writer.writerow([
                    domain.hostname,
                    domain.port,
                    domain.owner,
                    'Scan error',
                    'Failed',
                    f'Investigate: {latest_scan.error}'
                ])
                continue
            
            # Check each issue
            issues = self._get_issues(latest_scan)
            
            if not issues:
                writer.writerow([
                    domain.hostname,
                    domain.port,
                    domain.owner,
                    'None',
                    'Valid',
                    'No action required'
                ])
            else:
                for issue, action in issues:
                    writer.writerow([
                        domain.hostname,
                        domain.port,
                        domain.owner,
                        issue,
                        'Issues Found',
                        action
                    ])
        
        return output.getvalue()
    
    def generate_pdf_report(self):
        """Generate PDF remediation report for all domains"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        # Add logo at top
        try:
            logo_path = os.path.join(os.path.dirname(__file__), 'static', 'images', 'logo.png')
            if os.path.exists(logo_path):
                logo_img = Image(logo_path, width=200, height=None)
                story.append(logo_img)
                story.append(Spacer(1, 0.3*inch))
            else:
                # Fallback if logo not found
                title_style = ParagraphStyle(
                    'LogoFallback',
                    parent=self.styles['Heading1'],
                    fontSize=24,
                    textColor=colors.HexColor('#003366'),
                    spaceAfter=20,
                    alignment=1
                )
                story.append(Paragraph('SSLGuard - TLS Certificate Monitoring', title_style))
                story.append(Spacer(1, 0.2*inch))
        except Exception as e:
            print(f"Warning: Could not load logo: {e}")
            story.append(Spacer(1, 0.2*inch))
        
        # Generated date
        date_text = f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}'
        story.append(Paragraph(date_text, self.styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Get all domains
        domains = Domain.query.all()
        
        if not domains:
            story.append(Paragraph('No domains configured.', self.styles['Normal']))
        else:
            # Build table data
            table_data = [['Domain', 'Port', 'Owner', 'Issue', 'Status', 'Action']]
            
            for domain in domains:
                latest_scan = domain.get_latest_scan()
                
                if not latest_scan:
                    table_data.append([
                        domain.hostname,
                        str(domain.port),
                        domain.owner,
                        'No scan data',
                        'Unknown',
                        'Run a scan'
                    ])
                elif latest_scan.error:
                    table_data.append([
                        domain.hostname,
                        str(domain.port),
                        domain.owner,
                        'Scan error',
                        'Failed',
                        latest_scan.error[:30] + '...'
                    ])
                else:
                    issues = self._get_issues(latest_scan)
                    
                    if not issues:
                        table_data.append([
                            domain.hostname,
                            str(domain.port),
                            domain.owner,
                            'None',
                            'Valid',
                            'No action'
                        ])
                    else:
                        for idx, (issue, action) in enumerate(issues):
                            if idx == 0:
                                table_data.append([
                                    domain.hostname,
                                    str(domain.port),
                                    domain.owner,
                                    issue,
                                    'Issues',
                                    action[:30] + '...'
                                ])
                            else:
                                table_data.append(['', '', '', issue, '', action[:30] + '...'])
            
            # Create table
            table = Table(table_data, colWidths=[1.2*inch, 0.5*inch, 1*inch, 1.3*inch, 0.7*inch, 1.3*inch])
            
            # Style table
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#003366')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
            ]))
            
            story.append(table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _get_issues(self, scan):
        """Extract issues from a scan result"""
        issues = []
        
        # Expiry issues
        if scan.expiry_status == 'Expired':
            issues.append(('Certificate Expired', 'Renew the certificate immediately'))
        elif scan.expiry_status == 'Expiring Soon':
            days = (scan.valid_to - datetime.utcnow()).days if scan.valid_to else 0
            issues.append(('Certificate Expiring Soon', f'Renew the certificate (expires in {days} days)'))
        
        # Chain issues
        if scan.chain_status == 'Self-signed':
            issues.append(('Self-signed Certificate', 'Replace with a CA-signed certificate'))
        elif scan.chain_status == 'Untrusted Root':
            issues.append(('Untrusted Root CA', 'Install the full certificate chain'))
        elif scan.chain_status == 'Incomplete':
            issues.append(('Incomplete Chain', 'Install all intermediate certificates'))
        
        # Hostname issues
        if not scan.hostname_valid:
            issues.append(('Hostname Mismatch', 'Reissue the certificate with the correct domain name'))
        
        return issues
