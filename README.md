# ExtractCert

**ExtractCert** is a Python tool for extracting and analyzing SSL/TLS certificates from URLs or certificate files in PEM or DER formats. This tool provides detailed insights into the retrieved certificates, including public keys and their corresponding fingerprints (SHA-256 and SHA-1).

## Usage
Retrieving a Certificate from a URL

You can extract the SSL/TLS certificate from any given URL using the -u flag.

```bash
python3 test.py -u <URL>
```

Using a Certificate File as Input

You can also load a certificate from a file in either PEM or DER format using the -f flag.

```bash
python3 test.py -f <cert_file>
```

## Features

- Retrieve SSL/TLS certificates from a specified URL.
- Load certificates from PEM or DER formatted files.
- Display the full certificate in PEM format.
- Extract and display public keys.
- Generate and show SHA-256 and SHA-1 fingerprints for both the certificate and public key.

## Installation

To run **ExtractCert**, you need to have Python 3 installed on your system. You can download Python from [python.org](https://www.python.org/downloads/).

### Prerequisites

Make sure you have the following packages installed:

- `cryptography`
- `pyOpenSSL`

You can install the required packages using pip:

```bash
pip install -r requirements.txt
