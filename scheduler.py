"""
SSLGuard Scheduler
Manages scheduled certificate scans using APScheduler.
"""

from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from models import db, Domain, Scan
from scanner import CertificateScanner, create_scan_record
from alerts import AlertManager
from config import DAILY_SCAN_HOUR


def scan_domain(domain_id):
    """Scan a single domain and save results"""
    from app import app
    
    with app.app_context():
        domain = Domain.query.get(domain_id)
        if not domain:
            return
        
        # Run scanner
        scanner = CertificateScanner(domain.hostname, domain.port)
        scan_data = scanner.scan()
        
        # Create scan record
        if scan_data:
            scan = create_scan_record(domain_id, scan_data)
            if scan:
                db.session.add(scan)
        else:
            # Record failed scan
            scan = Scan(
                domain_id=domain_id,
                error=scanner.error
            )
            db.session.add(scan)
        
        db.session.commit()
        
        # Check and send alerts
        alert_manager = AlertManager()
        alert_manager.check_and_send_alerts(domain)


def scan_all_domains():
    """Scan all approved domains"""
    from app import app
    
    with app.app_context():
        domains = Domain.query.all()
        for domain in domains:
            scan_domain(domain.id)


class ScanScheduler:
    """Manages scheduled scans"""
    
    def __init__(self):
        self.scheduler = BackgroundScheduler()
    
    def start(self):
        """Start the scheduler"""
        # Schedule daily scan at configured hour
        self.scheduler.add_job(
            func=scan_all_domains,
            trigger='cron',
            hour=DAILY_SCAN_HOUR,
            minute=0,
            id='daily_scan',
            replace_existing=True
        )
        
        if not self.scheduler.running:
            self.scheduler.start()
    
    def stop(self):
        """Stop the scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown()
