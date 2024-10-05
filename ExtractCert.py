import sys
import ssl
import hashlib
import base64
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
import socket

# Function to print the title in ASCII art
def print_title():
    title = r"""

___________         __                        __   _________                __   
\_   _____/__  ____/  |_____________    _____/  |_ \_   ___ \  ____________/  |_ 
 |    __)_\  \/  /\   __\_  __ \__  \ _/ ___\   __\/    \  \/_/ __ \_  __ \   __\
 |        \>    <  |  |  |  | \// __ \\  \___|  |  \     \___\  ___/|  | \/|  |  
/_______  /__/\_ \ |__|  |__|  (____  /\___  >__|   \______  /\___  >__|   |__|  
        \/      \/                  \/     \/              \/     \/             
                    \\\///__Shanuka_Ashen__///\\\

    """
    print(title)

# Function to load the certificate from a URL
def load_certificate_from_url(url):
    try:
        # Ensure URL doesn't contain https:// prefix for socket connection
        hostname = url.replace('https://', '').replace('http://', '')
        
        # Create socket and wrap it with SSL context
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                der_cert = sslsock.getpeercert(binary_form=True)
        
        # Convert to PEM format
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert_open_ssl = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
        return cert_open_ssl, pem_cert
    except Exception as e:
        print(f"Error retrieving certificate from URL: {e}")
        sys.exit(1)

# Function to load the certificate from a PEM or DER file
def load_certificate_from_file(cert_file):
    try:
        with open(cert_file, 'rb') as f:
            cert_data = f.read()

        # Check if the certificate is in DER format (binary)
        if cert_file.endswith('.der'):
            cert_open_ssl = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
            # Convert DER to PEM for display
            pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_open_ssl).decode('utf-8')
        else:
            # Assume PEM-encoded if not DER
            pem_cert = cert_data.decode('utf-8')
            cert_open_ssl = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)

        return cert_open_ssl, pem_cert

    except Exception as e:
        print(f"Error loading certificate from file: {e}")
        sys.exit(1)

# Function to print the certificate's PEM format
def print_certificate_pem(pem_cert):
    print("\n--- Retrieved Certificate ---\n")
    print(pem_cert)

# Function to print the public key
def print_public_key(cert):
    pub_key = cert.get_pubkey()
    pub_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, pub_key).decode('utf-8')
    print("\n--- Public Key ---")
    print(pub_key_pem)

# Function to print certificate and public key fingerprints
def print_fingerprints(cert):
    cert_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

    # Certificate Fingerprints
    sha256_fingerprint = hashlib.sha256(cert_bytes).hexdigest().upper()
    sha1_fingerprint = hashlib.sha1(cert_bytes).hexdigest().upper()

    print("\n--- Certificate Fingerprints ---")
    print(f"SHA-256 Fingerprint (Cert - Hex):      {sha256_fingerprint}")
    print(f"SHA-256 Fingerprint (Cert - Base64):   {base64.b64encode(hashlib.sha256(cert_bytes).digest()).decode('utf-8')}")

    print(f"\nSHA-1 Fingerprint (Cert - Hex):        {sha1_fingerprint}")
    print(f"SHA-1 Fingerprint (Cert - Base64):     {base64.b64encode(hashlib.sha1(cert_bytes).digest()).decode('utf-8')}")

    # Public Key Fingerprints
    pub_key = cert.get_pubkey()
    pub_key_bytes = crypto.dump_publickey(crypto.FILETYPE_ASN1, pub_key)

    sha256_pubkey_fingerprint = hashlib.sha256(pub_key_bytes).hexdigest().upper()
    sha1_pubkey_fingerprint = hashlib.sha1(pub_key_bytes).hexdigest().upper()

    print("\n--- Public Key Fingerprints ---")
    print(f"SHA-256 Fingerprint (PubKey - Hex):    {sha256_pubkey_fingerprint}")
    print(f"SHA-256 Fingerprint (PubKey - Base64): {base64.b64encode(hashlib.sha256(pub_key_bytes).digest()).decode('utf-8')}")

    print(f"\nSHA-1 Fingerprint (PubKey - Hex):      {sha1_pubkey_fingerprint}")
    print(f"SHA-1 Fingerprint (PubKey - Base64):   {base64.b64encode(hashlib.sha1(pub_key_bytes).digest()).decode('utf-8')}")

# Main function to handle the inputs and call the appropriate functions
def main():
    print_title()
    
    if len(sys.argv) < 2:
        print("Usage: python3 test.py [-u <URL> | -f <cert_file>]")
        sys.exit(1)

    if sys.argv[1] == '-u':
        if len(sys.argv) < 3:
            print("Usage: python3 test.py -u <URL>")
            sys.exit(1)
        url = sys.argv[2]
        cert, pem_cert = load_certificate_from_url(url)
        print_certificate_pem(pem_cert)
        print_public_key(cert)
        print_fingerprints(cert)

    elif sys.argv[1] == '-f':
        if len(sys.argv) < 3:
            print("Usage: python3 test.py -f <cert_file>")
            sys.exit(1)
        cert_file = sys.argv[2]
        cert, pem_cert = load_certificate_from_file(cert_file)
        print_certificate_pem(pem_cert)
        print_public_key(cert)
        print_fingerprints(cert)

    else:
        print("Invalid option. Use -u for URL or -f for certificate file.")
        sys.exit(1)

if __name__ == "__main__":
    main()
