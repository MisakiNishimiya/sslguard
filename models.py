"""
SSLGuard Models
Defines User, Domain, Scan, Alert, and AlertLog database tables.
"""

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    """User model - admin or viewer role"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')  # 'admin' or 'viewer'
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def set_password(self, password):
        """Hash and store password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if user is an admin"""
        return self.role == 'admin'
    
    def is_viewer(self):
        """Check if user is a viewer"""
        return self.role in ['admin', 'viewer']
    
    # Flask-Login required methods
    @property
    def is_authenticated(self):
        """Return True if the user is authenticated"""
        return True
    
    @property
    def is_active(self):
        """Return True if this is an active user"""
        return True
    
    @property
    def is_anonymous(self):
        """Return False as anonymous users aren't supported"""
        return False
    
    def get_id(self):
        """Return the user ID as a string"""
        return str(self.id)


class Domain(db.Model):
    """Approved domains for scanning"""
    __tablename__ = 'domains'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False, unique=True)
    port = db.Column(db.Integer, nullable=False, default=443)
    owner = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scans = db.relationship('Scan', backref='domain', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='domain', lazy=True, cascade='all, delete-orphan')
    
    def get_latest_scan(self):
        """Get the most recent scan for this domain"""
        return Scan.query.filter_by(domain_id=self.id).order_by(Scan.scan_time.desc()).first()


class Scan(db.Model):
    """Certificate scan results"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    scan_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Certificate details
    subject = db.Column(db.Text)  # Certificate subject
    issuer = db.Column(db.Text)   # Certificate issuer
    valid_from = db.Column(db.DateTime)  # notBefore
    valid_to = db.Column(db.DateTime)    # notAfter
    fingerprint_sha256 = db.Column(db.String(64))  # SHA-256 hex
    
    # Check results
    expiry_status = db.Column(db.String(20))  # 'Valid', 'Expiring Soon', 'Expired'
    chain_status = db.Column(db.String(50))   # 'Valid', 'Self-signed', 'Untrusted Root', 'Incomplete'
    hostname_valid = db.Column(db.Boolean)    # True or False
    
    # Scan metadata
    error = db.Column(db.Text)  # Error message if scan failed


class Alert(db.Model):
    """Email alert records - tracks which alerts have been sent"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)  # 'expiry_30', 'chain_issue', 'hostname_issue', etc.
    threshold_days = db.Column(db.Integer)  # For expiry alerts
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    email_sent = db.Column(db.Boolean, default=False)
    email_sent_at = db.Column(db.DateTime)


class AlertLog(db.Model):
    """Log of all alerts for audit trail"""
    __tablename__ = 'alert_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
