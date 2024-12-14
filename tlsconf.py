from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest, ScanCommand

def check_ssl_configuration(domain):
    server_location = ServerNetworkLocation(hostname=domain, port=443)
    scanner = Scanner()
    scan_request = ServerScanRequest(
        server_location=server_location,
        scan_commands=[ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES]
    )
    scanner.queue_scan(scan_request)
    for scan_result in scanner.get_results():
        print(f"Results for {domain}:")
        for command, result in scan_result.scan_commands_results.items():
            print(f"  {command}:")
            print(f"    {result.as_text()}")
            
# Example Usage
check_ssl_configuration("https://geekflare.com/online-scan-website-security-vulnerabilities/")