"""
SSLGuard - TLS Certificate Monitoring System
Main Flask application with routes and login.
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Domain, Scan
from config import SECRET_KEY, SQLALCHEMY_DATABASE_URI, STATUS_CRITICAL_DAYS, STATUS_WARNING_DAYS
from scanner import CertificateScanner, create_scan_record
from alerts import AlertManager, get_dashboard_alerts
from reports import ReportGenerator
from scheduler import ScanScheduler
from utils import parse_issuer_name, classify_cert_status
from datetime import datetime
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Make datetime available to all templates
@app.context_processor
def inject_now():
    """Inject current datetime into all templates"""
    return {'now': datetime.now}

# Initialize scheduler
scheduler = ScanScheduler()

# Create tables and start scheduler
with app.app_context():
    db.create_all()
    scheduler.start()


@login_manager.user_loader
def load_user(user_id):
    """Load user from database"""
    return User.query.get(int(user_id))


# Add cache control headers to prevent back button access after logout
@app.after_request
def add_security_headers(response):
    """Add security headers to prevent caching of authenticated pages"""
    if current_user.is_authenticated:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and handler"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return render_template('login.html', error='Username and password required')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=request.form.get('remember', False))
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    session.clear()
    response = redirect(url_for('login'))
    # Prevent caching of the logout response
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


# ============================================================================
# DASHBOARD ROUTE
# ============================================================================

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard - shows all domains and their status"""
    if not current_user.is_viewer():
        return redirect(url_for('login'))
    
    # Get all domains
    domains = Domain.query.all()
    
    # Initialize summary counters
    summary = {
        'expired': 0,
        'critical': 0,
        'warning': 0,
        'valid': 0,
        'error': 0
    }
    
    domain_data = []
    now = datetime.utcnow()
    
    for domain in domains:
        latest_scan = domain.get_latest_scan()
        
        if not latest_scan:
            # No scan yet
            summary['error'] += 1
            domain_data.append({
                'domain': domain,
                'status': 'error',
                'status_color': 'secondary',
                'status_label': 'No Scan',
                'status_icon': 'bi-question-circle',
                'days_until_expiry': None,
                'days_display': '—',
                'expiry_date': None,
                'issuer_short': 'Unknown',
                'issuer_full': 'Unknown',
                'last_scanned': None,
                'error_message': None
            })
        elif latest_scan.error:
            # Scan error
            summary['error'] += 1
            domain_data.append({
                'domain': domain,
                'status': 'error',
                'status_color': 'secondary',
                'status_label': 'Scan Error',
                'status_icon': 'bi-exclamation-circle',
                'days_until_expiry': None,
                'days_display': '—',
                'expiry_date': None,
                'issuer_short': 'Error',
                'issuer_full': latest_scan.error,
                'last_scanned': latest_scan.scan_time,
                'error_message': latest_scan.error
            })
        else:
            # Valid scan with certificate data
            days_until_expiry = (latest_scan.valid_to - now).days if latest_scan.valid_to else 0
            
            # Classify status
            status, status_color, status_icon = classify_cert_status(days_until_expiry)
            
            # Update summary
            summary[status] += 1
            
            # Status label
            if status == 'expired':
                status_label = 'Expired'
                days_display = f"Expired {abs(days_until_expiry)} days ago"
            elif status == 'critical':
                status_label = 'Critical'
                days_display = f"{days_until_expiry} days"
            elif status == 'warning':
                status_label = 'Warning'
                days_display = f"{days_until_expiry} days"
            else:
                status_label = 'Valid'
                days_display = f"{days_until_expiry} days"
            
            # Parse issuer
            issuer_short, issuer_full = parse_issuer_name(latest_scan.issuer)
            
            domain_data.append({
                'domain': domain,
                'status': status,
                'status_color': status_color,
                'status_label': status_label,
                'status_icon': status_icon,
                'days_until_expiry': days_until_expiry,
                'days_display': days_display,
                'expiry_date': latest_scan.valid_to,
                'issuer_short': issuer_short,
                'issuer_full': issuer_full,
                'last_scanned': latest_scan.scan_time,
                'error_message': None
            })
    
    # Sort: expired first, then by days (ascending), errors last
    def sort_key(item):
        if item['status'] == 'error':
            return (3, 99999)  # Errors last
        elif item['status'] == 'expired':
            return (0, -item['days_until_expiry'] if item['days_until_expiry'] else 0)  # Most expired first
        elif item['days_until_expiry'] is not None:
            return (1, item['days_until_expiry'])  # Soonest expiry first
        else:
            return (2, 0)
    
    domain_data.sort(key=sort_key)
    
    return render_template('dashboard.html', domain_data=domain_data, summary=summary)


# ============================================================================
# DOMAIN MANAGEMENT ROUTES (ADMIN ONLY)
# ============================================================================

@app.route('/domains')
@login_required
def domains():
    """Domain inventory page"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    domains_list = Domain.query.all()
    return render_template('domains.html', domains=domains_list)


@app.route('/domain/add', methods=['GET', 'POST'])
@login_required
def add_domain():
    """Add a new domain"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip().lower()
        port = request.form.get('port', '443').strip()
        owner = request.form.get('owner', '').strip()
        
        # Validation
        if not hostname or not owner:
            return render_template('add_domain.html', error='Hostname and owner are required')
        
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError()
        except:
            return render_template('add_domain.html', error='Port must be a valid number between 1 and 65535')
        
        # Check if domain already exists
        existing = Domain.query.filter_by(hostname=hostname, port=port).first()
        if existing:
            return render_template('add_domain.html', error='Domain already exists')
        
        # Add domain
        domain = Domain(hostname=hostname, port=port, owner=owner)
        db.session.add(domain)
        db.session.commit()
        
        return redirect(url_for('domains'))
    
    return render_template('add_domain.html')


@app.route('/domain/<int:domain_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_domain(domain_id):
    """Edit a domain"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    domain = Domain.query.get_or_404(domain_id)
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip().lower()
        port = request.form.get('port', '443').strip()
        owner = request.form.get('owner', '').strip()
        
        # Validation
        if not hostname or not owner:
            return render_template('edit_domain.html', domain=domain, error='Hostname and owner are required')
        
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError()
        except:
            return render_template('edit_domain.html', domain=domain, error='Port must be a valid number between 1 and 65535')
        
        # Check if domain already exists (different from current)
        existing = Domain.query.filter_by(hostname=hostname, port=port).first()
        if existing and existing.id != domain.id:
            return render_template('edit_domain.html', domain=domain, error='Domain already exists')
        
        # Update domain
        domain.hostname = hostname
        domain.port = port
        domain.owner = owner
        db.session.commit()
        
        return redirect(url_for('domains'))
    
    return render_template('edit_domain.html', domain=domain)


@app.route('/domain/<int:domain_id>/delete', methods=['POST'])
@login_required
def delete_domain(domain_id):
    """Delete a domain"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    domain = Domain.query.get_or_404(domain_id)
    db.session.delete(domain)
    db.session.commit()
    
    return redirect(url_for('domains'))


# ============================================================================
# SCANNING ROUTES (ADMIN ONLY)
# ============================================================================

@app.route('/domain/<int:domain_id>/scan', methods=['POST'])
@login_required
def scan_domain(domain_id):
    """Scan a single domain"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    domain = Domain.query.get_or_404(domain_id)
    
    # Run scanner
    scanner = CertificateScanner(domain.hostname, domain.port)
    scan_data = scanner.scan()
    
    # Save results
    if scan_data:
        scan = create_scan_record(domain_id, scan_data)
        if scan:
            db.session.add(scan)
    else:
        scan = Scan(domain_id=domain_id, error=scanner.error)
        db.session.add(scan)
    
    db.session.commit()
    
    # Check alerts
    alert_manager = AlertManager()
    alert_manager.check_and_send_alerts(domain)
    
    return jsonify({'success': True})


@app.route('/scan-all', methods=['POST'])
@login_required
def scan_all():
    """Scan all domains"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    domains = Domain.query.all()
    
    for domain in domains:
        scanner = CertificateScanner(domain.hostname, domain.port)
        scan_data = scanner.scan()
        
        if scan_data:
            scan = create_scan_record(domain.id, scan_data)
            if scan:
                db.session.add(scan)
        else:
            scan = Scan(domain_id=domain.id, error=scanner.error)
            db.session.add(scan)
        
        db.session.commit()
        
        alert_manager = AlertManager()
        alert_manager.check_and_send_alerts(domain)
    
    return jsonify({'success': True, 'scanned': len(domains)})


# ============================================================================
# SCAN HISTORY ROUTE
# ============================================================================

@app.route('/domain/<int:domain_id>/history')
@login_required
def scan_history(domain_id):
    """Scan history for a domain"""
    if not current_user.is_viewer():
        return redirect(url_for('login'))
    
    domain = Domain.query.get_or_404(domain_id)
    scans = Scan.query.filter_by(domain_id=domain_id).order_by(Scan.scan_time.desc()).all()
    
    return render_template('history.html', domain=domain, scans=scans)


# ============================================================================
# REPORTS ROUTES (ADMIN ONLY)
# ============================================================================

@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    return render_template('reports.html')


@app.route('/report/csv')
@login_required
def export_csv():
    """Export remediation report as CSV"""
    if not current_user.is_admin():
        return redirect(url_for('login'))
    
    generator = ReportGenerator()
    csv_data = generator.generate_csv_report()
    
    return send_file(
        io.BytesIO(csv_data.encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'sslguard_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@app.route('/report/pdf')
@login_required
def export_pdf():
    """Export remediation report as PDF"""
    if not current_user.is_admin():
        return redirect(url_for('login'))
    
    generator = ReportGenerator()
    pdf_data = generator.generate_pdf_report()
    
    return send_file(
        io.BytesIO(pdf_data),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'sslguard_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.pdf'
    )


# ============================================================================
# USER MANAGEMENT ROUTES (ADMIN ONLY)
# ============================================================================

@app.route('/users')
@login_required
def users():
    """User management page"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    users_list = User.query.all()
    
    # Handle flash message from session (for POST-redirect-GET pattern)
    if 'flash_message' in session:
        category, message = session.pop('flash_message')
        flash(message, category)
    
    return render_template('users.html', users=users_list, user_count=len(users_list))


@app.route('/user/add', methods=['GET', 'POST'])
@login_required
def add_user():
    """Add a new user"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'viewer')
        
        # Validation
        if not username or not password:
            return render_template('add_user.html', error='Username and password are required')
        
        if password != confirm_password:
            return render_template('add_user.html', error='Passwords do not match')
        
        if len(password) < 6:
            return render_template('add_user.html', error='Password must be at least 6 characters')
        
        if role not in ['admin', 'viewer']:
            return render_template('add_user.html', error='Invalid role')
        
        # Check if user exists
        existing = User.query.filter_by(username=username).first()
        if existing:
            return render_template('add_user.html', error='Username already exists')
        
        # Create user
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('users'))
    
    return render_template('add_user.html')


@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    """Edit a user"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        role = request.form.get('role', 'viewer')
        password = request.form.get('password', '')
        
        if role not in ['admin', 'viewer']:
            return render_template('edit_user.html', user=user, error='Invalid role')
        
        user.role = role
        
        if password:
            if len(password) < 6:
                return render_template('edit_user.html', user=user, error='Password must be at least 6 characters')
            user.set_password(password)
        
        db.session.commit()
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user)


@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user"""
    if not current_user.is_admin():
        return redirect(url_for('dashboard'))
    
    # Prevent deleting self
    if user_id == current_user.id:
        session['flash_message'] = ('error', 'You cannot delete your own account')
        return redirect(url_for('users'))
    
    # Check if this is the last admin
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count <= 1:
            session['flash_message'] = ('error', 'Cannot delete the last administrator account')
            return redirect(url_for('users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    session['flash_message'] = ('success', f'User "{username}" has been deleted')
    return redirect(url_for('users'))


@app.route('/user/<int:user_id>/reset-password', methods=['POST'])
@login_required
def reset_password(user_id):
    """Reset user password - TODO: Implement password reset logic"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    
    # TODO: Generate temporary password and send via email
    # TODO: Or generate reset link and send via email
    # For now, just return a placeholder response
    
    session['flash_message'] = ('warning', f'Password reset for "{user.username}" - Feature not yet implemented')
    return redirect(url_for('users'))


@app.route('/user/<int:user_id>/toggle-status', methods=['POST'])
@login_required  
def toggle_user_status(user_id):
    """Enable/Disable user - TODO: Add status field to User model"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Prevent disabling self
    if user_id == current_user.id:
        session['flash_message'] = ('error', 'You cannot disable your own account')
        return redirect(url_for('users'))
    
    user = User.query.get_or_404(user_id)
    
    # TODO: Add 'is_active' or 'status' field to User model
    # TODO: Then implement: user.is_active = not user.is_active
    
    session['flash_message'] = ('warning', f'Enable/Disable for "{user.username}" - Feature requires database migration (add is_active field)')
    return redirect(url_for('users'))


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('error.html', error='Page not found'), 404


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return render_template('error.html', error='Internal server error'), 500


# Add import for io
import io


if __name__ == '__main__':
    # Run Flask development server
    # If you get "socket access forbidden" error, try:
    # 1. Run VS Code as Administrator
    # 2. Check Windows Firewall: allow Python through firewall
    # 3. Disable antivirus temporarily
    # Alternative ports: 8000, 8080, 8888, 3000
    app.run(debug=True, host='127.0.0.1', port=8000)
