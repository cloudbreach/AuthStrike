import os
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")

TENANT_ID = os.getenv("TENANT_ID", "common")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read"]
SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev")
RESOURCE = os.getenv("RESOURCE") or "https://graph.microsoft.com"