import requests

def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers

    # Common security headers to check
    security_headers = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy',
        'Strict-Transport-Security'
    ]

    missing_headers = [h for h in security_headers if h not in headers]
    if missing_headers:
        print(f"Missing security headers on {url}: {missing_headers}")
    else:
        print(f"All recommended security headers are present on {url}.")

# Example Usage
check_security_headers('https://www.hackthebox.com')
