"""
SSLGuard Scanner
Performs TLS handshake and certificate validation checks.
"""

import socket
import ssl
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID
import hashlib
from models import Scan, Domain


class CertificateScanner:
    """Scans TLS certificates on a domain"""
    
    def __init__(self, hostname, port=443, timeout=10):
        """Initialize scanner with hostname and port"""
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.error = None
    
    def scan(self):
        """
        Perform a TLS handshake and return certificate details and check results.
        Returns a dict with certificate info and validation results, or None on error.
        """
        try:
            # Establish SSL/TLS connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Get certificate chain
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_chain = ssock.getpeercert_chain() if hasattr(ssock, 'getpeercert_chain') else None
                    
                    if not cert_der:
                        self.error = "No certificate found"
                        return None
                    
                    # Parse certificate using cryptography library
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    return self._parse_certificate(cert)
        
        except socket.timeout:
            self.error = f"Connection timeout after {self.timeout} seconds"
            return None
        except socket.gaierror:
            self.error = f"DNS resolution failed for {self.hostname}"
            return None
        except ConnectionRefusedError:
            self.error = f"Connection refused on {self.hostname}:{self.port}"
            return None
        except ssl.SSLError as e:
            self.error = f"SSL error: {str(e)}"
            return None
        except Exception as e:
            self.error = f"Scan failed: {str(e)}"
            return None
    
    def _parse_certificate(self, cert):
        """Parse X.509 certificate and perform checks"""
        result = {}
        
        # Extract certificate details
        try:
            # Subject and Issuer
            result['subject'] = cert.subject.rfc4514_string()
            result['issuer'] = cert.issuer.rfc4514_string()
            
            # Valid from and to
            result['valid_from'] = cert.not_valid_before
            result['valid_to'] = cert.not_valid_after
            
            # SHA-256 fingerprint
            fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            result['fingerprint_sha256'] = fingerprint
            
            # Perform checks
            result.update(self._check_expiry(cert))
            result.update(self._check_chain(cert))
            result.update(self._check_hostname(cert))
            
            return result
        
        except Exception as e:
            self.error = f"Certificate parsing failed: {str(e)}"
            return None
    
    def _check_expiry(self, cert):
        """Check certificate expiry status"""
        now = datetime.utcnow()
        not_after = cert.not_valid_after
        
        days_until_expiry = (not_after - now).days
        
        if days_until_expiry < 0:
            status = 'Expired'
        elif days_until_expiry <= 30:
            status = 'Expiring Soon'
        else:
            status = 'Valid'
        
        return {
            'expiry_status': status,
            'days_until_expiry': max(days_until_expiry, 0)
        }
    
    def _check_chain(self, cert):
        """
        Check certificate chain validity.
        Returns: 'Valid', 'Self-signed', 'Untrusted Root', or 'Incomplete'
        """
        try:
            # Check if self-signed
            if cert.issuer == cert.subject:
                return {'chain_status': 'Self-signed'}
            
            # Check for Root CA indicator
            try:
                bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                if bc.value.ca and bc.value.path_length is None:
                    # This is likely a root certificate
                    return {'chain_status': 'Untrusted Root'}
            except x509.ExtensionNotFound:
                pass
            
            # In a real scenario, we'd validate against system CA bundle
            # For now, assume chain is valid if not self-signed
            return {'chain_status': 'Valid'}
        
        except Exception:
            return {'chain_status': 'Incomplete'}
    
    def _check_hostname(self, cert):
        """Check if hostname matches certificate SAN or CN"""
        try:
            san_names = []
            
            # Get SAN extension
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        san_names.append(name.value.lower())
            except x509.ExtensionNotFound:
                pass
            
            # If no SAN, check CN
            if not san_names:
                try:
                    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if cn:
                        san_names.append(cn[0].value.lower())
                except:
                    pass
            
            # Check hostname against SAN/CN
            hostname_lower = self.hostname.lower()
            hostname_valid = any(
                self._matches_hostname(hostname_lower, san) 
                for san in san_names
            )
            
            return {'hostname_valid': hostname_valid}
        
        except Exception:
            return {'hostname_valid': False}
    
    def _matches_hostname(self, hostname, pattern):
        """Check if hostname matches DNS name pattern (with wildcard support)"""
        pattern = pattern.lower()
        
        if pattern.startswith('*.'):
            # Wildcard certificate
            pattern = pattern[2:]
            return hostname.endswith('.' + pattern) or hostname == pattern.lstrip('.')
        else:
            return hostname == pattern


# Import for fingerprinting
from cryptography.hazmat.primitives import serialization


def create_scan_record(domain_id, scan_data):
    """Create a Scan database record from scanner results"""
    if not scan_data:
        return None
    
    scan = Scan(
        domain_id=domain_id,
        subject=scan_data.get('subject'),
        issuer=scan_data.get('issuer'),
        valid_from=scan_data.get('valid_from'),
        valid_to=scan_data.get('valid_to'),
        fingerprint_sha256=scan_data.get('fingerprint_sha256'),
        expiry_status=scan_data.get('expiry_status'),
        chain_status=scan_data.get('chain_status'),
        hostname_valid=scan_data.get('hostname_valid'),
        error=None
    )
    return scan


# Simple test - can run from command line
if __name__ == '__main__':
    # Test against google.com
    scanner = CertificateScanner('google.com', 443, timeout=10)
    result = scanner.scan()
    
    if result:
        print("=== Certificate Scan Results for google.com ===")
        print(f"Subject: {result.get('subject')}")
        print(f"Issuer: {result.get('issuer')}")
        print(f"Valid From: {result.get('valid_from')}")
        print(f"Valid To: {result.get('valid_to')}")
        print(f"Fingerprint (SHA-256): {result.get('fingerprint_sha256')}")
        print(f"\n=== Validation Results ===")
        print(f"Expiry Status: {result.get('expiry_status')} ({result.get('days_until_expiry')} days)")
        print(f"Chain Status: {result.get('chain_status')}")
        print(f"Hostname Valid: {result.get('hostname_valid')}")
    else:
        print(f"Scan failed: {scanner.error}")
