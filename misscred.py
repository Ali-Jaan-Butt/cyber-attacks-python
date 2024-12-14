import requests

def test_privilege_escalation(base_url, user_session, admin_resource):
    # user_session should be a session object logged in as a regular user
    response = user_session.get(f"{base_url}/{admin_resource}")
    if response.status_code == 200:
        print("Security Flaw: Regular user can access admin resource!")
    else:
        print("Access appropriately restricted.")

# Setup session for a regular user
user_session = requests.Session()
user_session.auth = ('regular_user', 'password')  # Example credentials

# Example usage
test_privilege_escalation('https://www.hackthebox.com', user_session, 'admin_panel')

def test_horizontal_privilege_escalation(base_url, user_session, other_user_resource):
    response = user_session.get(f"{base_url}/{other_user_resource}")
    if response.status_code == 200:
        print("Security Flaw: User can access another user's data!")
    else:
        print("User data is properly isolated.")

# Example usage with the same user_session
test_horizontal_privilege_escalation('https://www.hackthebox.com', user_session, 'user/12345/data')  # Assuming 12345 is another user's ID

def test_missing_authorization(base_url, endpoints):
    # No session, direct requests
    for endpoint in endpoints:
        response = requests.get(f"{base_url}/{endpoint}")
        if response.status_code == 200:
            print(f"Security Flaw: Unauthenticated access to {endpoint}!")
        else:
            print(f"Access to {endpoint} is secured.")

# Example endpoints that should require authorization
secure_endpoints = ['profile', 'settings', 'dashboard']
test_missing_authorization('https://www.hackthebox.com', secure_endpoints)
