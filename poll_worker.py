import os
os.environ["AUTHSTRIKE_DISABLE_POLL_DISPATCHER"] = "true"
from app import dispatch_poll_jobs

if __name__ == "__main__":
    dispatch_poll_jobs()
