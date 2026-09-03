#!/usr/bin/env python3
"""Create a Werkzeug password hash for AUTHSTRIKE_ADMIN_PASSWORD_HASH."""
from getpass import getpass
from werkzeug.security import generate_password_hash

password = getpass("New AuthStrike admin password: ")
confirm = getpass("Confirm password: ")
if not password or password != confirm:
    raise SystemExit("Passwords are empty or do not match.")
print("\nSet AUTHSTRIKE_ADMIN_PASSWORD_HASH to:\n")
print(generate_password_hash(password))
