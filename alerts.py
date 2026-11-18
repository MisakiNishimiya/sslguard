"""
SSLGuard Alerts
Manages email alerts for certificate issues and expirations.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from models import Alert, AlertLog, Scan, Domain
from config import (
    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, 
    SMTP_FROM_EMAIL, ALERT_THRESHOLDS
)


class AlertManager:
    """Manages certificate alerts and email notifications"""
    
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.smtp_username = SMTP_USERNAME
        self.smtp_password = SMTP_PASSWORD
        self.from_email = SMTP_FROM_EMAIL
    
    def check_and_send_alerts(self, domain):
        """Check domain for issues and send alerts if needed"""
        latest_scan = domain.get_latest_scan()
        
        if not latest_scan or latest_scan.error:
            return
        
        # Check expiry alerts
        self._handle_expiry_alerts(domain, latest_scan)
        
        # Check chain issues
        self._handle_chain_alerts(domain, latest_scan)
        
        # Check hostname issues
        self._handle_hostname_alerts(domain, latest_scan)
    
    def _handle_expiry_alerts(self, domain, scan):
        """Check expiry thresholds and send alerts"""
        if not scan.valid_to:
            return
        
        days_until_expiry = (scan.valid_to - datetime.utcnow()).days
        
        # Check each threshold
        for threshold in ALERT_THRESHOLDS:
            alert_type = f'expiry_{threshold}'
            
            # Only send if expiry is close enough and alert not already sent
            if days_until_expiry <= threshold:
                # Check if we already sent this alert
                existing = Alert.query.filter_by(
                    domain_id=domain.id,
                    alert_type=alert_type,
                    email_sent=True
                ).first()
                
                if not existing:
                    # Send email
                    subject = f"Certificate Expiry Alert: {domain.hostname}"
                    message = f"""
Certificate for {domain.hostname} will expire in {days_until_expiry} days.

Domain: {domain.hostname}:{domain.port}
Owner: {domain.owner}
Valid Until: {scan.valid_to.strftime('%Y-%m-%d %H:%M:%S')}
Issued By: {scan.issuer}

Please renew the certificate before expiry.
"""
                    self._send_email(subject, message)
                    
                    # Mark alert as sent
                    alert = Alert(
                        domain_id=domain.id,
                        alert_type=alert_type,
                        threshold_days=threshold,
                        email_sent=True,
                        email_sent_at=datetime.utcnow()
                    )
                    # Log would be saved by scheduler context
    
    def _handle_chain_alerts(self, domain, scan):
        """Send alert if chain validation fails"""
        if scan.chain_status not in ['Self-signed', 'Untrusted Root', 'Incomplete']:
            return
        
        alert_type = 'chain_issue'
        
        # Check if alert already sent
        existing = Alert.query.filter_by(
            domain_id=domain.id,
            alert_type=alert_type,
            email_sent=True
        ).first()
        
        if not existing:
            subject = f"Certificate Chain Issue: {domain.hostname}"
            message = f"""
Certificate chain validation failed for {domain.hostname}.

Domain: {domain.hostname}:{domain.port}
Owner: {domain.owner}
Issue: {scan.chain_status}

Action Required:
- If self-signed: Replace with a valid CA-signed certificate
- If untrusted root: Install the full certificate chain
- If incomplete: Ensure all intermediate certificates are installed
"""
            self._send_email(subject, message)
            
            alert = Alert(
                domain_id=domain.id,
                alert_type=alert_type,
                email_sent=True,
                email_sent_at=datetime.utcnow()
            )
    
    def _handle_hostname_alerts(self, domain, scan):
        """Send alert if hostname validation fails"""
        if scan.hostname_valid:
            return
        
        alert_type = 'hostname_issue'
        
        # Check if alert already sent
        existing = Alert.query.filter_by(
            domain_id=domain.id,
            alert_type=alert_type,
            email_sent=True
        ).first()
        
        if not existing:
            subject = f"Certificate Hostname Mismatch: {domain.hostname}"
            message = f"""
Certificate hostname validation failed for {domain.hostname}.

Domain: {domain.hostname}:{domain.port}
Owner: {domain.owner}
Certificate Subject: {scan.subject}

The domain does not match the certificate's SAN or CN.

Action Required:
- Reissue the certificate with the correct domain name(s)
- Or update the domain to match the certificate
"""
            self._send_email(subject, message)
            
            alert = Alert(
                domain_id=domain.id,
                alert_type=alert_type,
                email_sent=True,
                email_sent_at=datetime.utcnow()
            )
    
    def _send_email(self, subject, message):
        """Send email alert"""
        if not all([self.smtp_server, self.smtp_username, self.smtp_password, self.from_email]):
            # SMTP not configured
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = self.from_email  # Send to admin email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'plain'))
            
            # Send via SMTP
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            return True
        
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
            return False


def get_dashboard_alerts(domain):
    """Get current alerts for dashboard display"""
    alerts = []
    latest_scan = domain.get_latest_scan()
    
    if not latest_scan:
        return alerts
    
    # Expiry alert
    if latest_scan.expiry_status == 'Expired':
        alerts.append({
            'type': 'danger',
            'message': 'Certificate has expired',
            'icon': '⚠️'
        })
    elif latest_scan.expiry_status == 'Expiring Soon':
        days = (latest_scan.valid_to - datetime.utcnow()).days
        alerts.append({
            'type': 'warning',
            'message': f'Certificate expires in {days} days',
            'icon': '⚠️'
        })
    
    # Chain alert
    if latest_scan.chain_status != 'Valid':
        alerts.append({
            'type': 'danger',
            'message': f'Chain validation issue: {latest_scan.chain_status}',
            'icon': '🔗'
        })
    
    # Hostname alert
    if not latest_scan.hostname_valid:
        alerts.append({
            'type': 'danger',
            'message': 'Hostname does not match certificate',
            'icon': '🔐'
        })
    
    return alerts
