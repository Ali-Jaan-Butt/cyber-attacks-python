from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerScanRequest,
    Scanner,
    ScanCommand
)

def analyze_ssl(host, port):
    # Specify the server and port number
    server_location = ServerNetworkLocationViaDirectConnection(hostname=host, port=port)
    scan_request = ServerScanRequest(
        server_location=server_location, 
        scan_commands={ScanCommand.SSL_3_0_CIPHER_SUITES}
    )
    
    # Perform the scan
    scanner = Scanner()
    scanner.queue_scan(scan_request)
    for scan_result in scanner.get_results():
        print(f"TLS scan results for {host}:")
        for command, result in scan_result.scan_commands_results.items():
            print(f"Command {command} - {result.as_text()}")

# Example Usage
analyze_ssl("https://www.hackthebox.com", 443)

import hashlib

def check_hash_security(data):
    # Example of a weak hash (MD5)
    md5_hash = hashlib.md5(data).hexdigest()
    print(f"MD5: {md5_hash}")

    # More secure hash (SHA-256)
    sha256_hash = hashlib.sha256(data).hexdigest()
    print(f"SHA-256: {sha256_hash}")

# Example usage
check_hash_security(b"Secure this data!")

from cryptography.fernet import Fernet

def test_encryption():
    # Generate a key and instantiate a Fernet instance
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    # Encrypt some data
    text = b"Encrypt this text!"
    encrypted_text = cipher_suite.encrypt(text)
    print(f"Encrypted: {encrypted_text}")

    # Decrypt the data
    decrypted_text = cipher_suite.decrypt(encrypted_text)
    print(f"Decrypted: {decrypted_text}")

# Example usage
test_encryption()
