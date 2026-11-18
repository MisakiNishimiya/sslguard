"""
SSLGuard Utility Functions
Helper functions for certificate data processing
"""

import re


def parse_issuer_name(issuer_dn):
    """
    Parse issuer distinguished name and extract organization or CN.
    
    Args:
        issuer_dn: Distinguished name string (e.g., "CN=Let's Encrypt, O=Let's Encrypt, C=US")
    
    Returns:
        Tuple of (short_name, full_dn) where short_name is the organization or CN
    """
    if not issuer_dn:
        return ("Unknown", "Unknown")
    
    # Parse the DN components
    components = {}
    
    # Match patterns like "CN=Value", "O=Value", "C=Value"
    # Handle escaped commas and quotes
    parts = re.findall(r'([A-Z]+)=([^,]+|"[^"]*")', issuer_dn)
    
    for key, value in parts:
        # Remove quotes if present
        value = value.strip('"').strip()
        if value:  # Only store non-empty values
            components[key] = value
    
    # Prefer Organization (O), fallback to Common Name (CN), then Organizational Unit (OU)
    short_name = (
        components.get('O') or 
        components.get('CN') or 
        components.get('OU') or 
        'Unknown'
    )
    
    return (short_name, issuer_dn)


def classify_cert_status(days_until_expiry, has_error=False):
    """
    Classify certificate status based on days until expiry.
    
    Args:
        days_until_expiry: Number of days until certificate expires (can be negative)
        has_error: Whether the scan had an error
    
    Returns:
        Tuple of (status, status_color, icon) where:
        - status: 'expired', 'critical', 'warning', 'valid', or 'error'
        - status_color: Bootstrap color class
        - icon: Bootstrap icon class
    """
    from config import STATUS_CRITICAL_DAYS, STATUS_WARNING_DAYS
    
    if has_error:
        return ('error', 'secondary', 'bi-exclamation-circle')
    
    if days_until_expiry < 0:
        return ('expired', 'danger', 'bi-x-circle')
    elif days_until_expiry <= STATUS_CRITICAL_DAYS:
        return ('critical', 'danger', 'bi-exclamation-triangle-fill')
    elif days_until_expiry <= STATUS_WARNING_DAYS:
        return ('warning', 'warning', 'bi-exclamation-triangle')
    else:
        return ('valid', 'success', 'bi-shield-check')
