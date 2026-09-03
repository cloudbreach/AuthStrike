#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Guard against running a stray copy of this script from the wrong directory.
[[ -f "$PROJECT_ROOT/app.py" && -f "$PROJECT_ROOT/requirements.txt" ]] || {
    echo "PROJECT_ROOT ($PROJECT_ROOT) doesn't look like the app root. Aborting."
    exit 1
}

PY=$(command -v python3 || command -v python) || { echo "python not found on PATH."; exit 1; }

read -r -p "Azure Resource Group: " RESOURCE_GROUP
read -r -p "Azure Web App name: " WEBAPP_NAME

if [[ -z "$RESOURCE_GROUP" || -z "$WEBAPP_NAME" ]]; then
    echo "Resource group and Web App name are required."
    exit 1
fi

ZIP_FILE="deployment.zip"
DESIRED_STARTUP="gunicorn --bind=0.0.0.0:8000 app:app"

echo "Logging into Azure..."
az login

echo
echo "Current Azure account:"
az account show -o table || {
    echo "No active subscription. Run: az account set --subscription <id>"
    exit 1
}

echo
echo "Retrieving App Service URL..."
DEFAULT_HOSTNAME=$(az webapp show \
    --resource-group "$RESOURCE_GROUP" \
    --name "$WEBAPP_NAME" \
    --query "defaultHostName" -o tsv)

URL="https://${DEFAULT_HOSTNAME}"
echo "Application URL determined: $URL"

# Track whether we change anything that restarts the app; only then do we need
# to give Kudu a moment before deploying.
SETTINGS_CHANGED=false

echo
echo "Checking startup command..."
CUR_STARTUP=$(az webapp config show \
    --resource-group "$RESOURCE_GROUP" \
    --name "$WEBAPP_NAME" \
    --query "appCommandLine" -o tsv)
if [[ "$CUR_STARTUP" == "$DESIRED_STARTUP" ]]; then
    echo "  already correct; skipping."
else
    echo "  setting (this restarts the app)..."
    az webapp config set \
        --resource-group "$RESOURCE_GROUP" \
        --name "$WEBAPP_NAME" \
        --startup-file "$DESIRED_STARTUP" \
        -o none
    SETTINGS_CHANGED=true
fi

echo
echo "Checking application settings..."
CURRENT=$(az webapp config appsettings list \
    --resource-group "$RESOURCE_GROUP" \
    --name "$WEBAPP_NAME" \
    --query "[].[name,value]" -o tsv)
has_setting() { awk -F'\t' -v k="$1" '$1==k{f=1} END{exit !f}' <<<"$CURRENT"; }
get_val()     { awk -F'\t' -v k="$1" '$1==k{print $2; exit}' <<<"$CURRENT"; }

# First-time build flag: the Kudu build service needs a moment to pick it up
# before we deploy (otherwise the deploy runs with no pip install).
NEED_BUILD_WAIT=false
has_setting SCM_DO_BUILD_DURING_DEPLOYMENT || NEED_BUILD_WAIT=true

# Build the list of settings that actually need changing (avoids a needless
# restart, and a restart mid-deploy is what drops the Kudu connection).
TO_SET=()
want() { [[ "$(get_val "$1")" == "$2" ]] || TO_SET+=("$1=$2"); }
want SCM_DO_BUILD_DURING_DEPLOYMENT true
want AUTHSTRIKE_ADMIN_USERNAME       admin
want AUTHSTRIKE_HTTPS                true
want STORE_RAW_TOKENS               false
want FLASK_DEBUG                    false

# FLASK_SECRET_KEY — generated once; never rotated (rotating logs everyone out).
if has_setting FLASK_SECRET_KEY; then
    echo "  FLASK_SECRET_KEY: already set."
else
    echo "  FLASK_SECRET_KEY: generating..."
    TO_SET+=("FLASK_SECRET_KEY=$("$PY" -c "import secrets; print(secrets.token_urlsafe(48))")")
fi

# AUTHSTRIKE_ADMIN_PASSWORD_HASH — generated once via the helper script.
if has_setting AUTHSTRIKE_ADMIN_PASSWORD_HASH; then
    echo "  AUTHSTRIKE_ADMIN_PASSWORD_HASH: already set."
else
    HASH_SCRIPT="$SCRIPT_DIR/create_password_hash.py"
    [[ -f "$HASH_SCRIPT" ]] || HASH_SCRIPT="$PROJECT_ROOT/scripts/create_password_hash.py"
    [[ -f "$HASH_SCRIPT" ]] || { echo "  create_password_hash.py not found."; exit 1; }

    echo "  AUTHSTRIKE_ADMIN_PASSWORD_HASH: creating admin password (follow the prompt)..."
    ADMIN_HASH=$("$PY" "$HASH_SCRIPT" | tail -n1)
    # If your helper takes the password as an ARGUMENT instead of prompting, use:
    #   ADMIN_HASH=$("$PY" "$HASH_SCRIPT" "<plaintext-password>" | tail -n1)
    case "$ADMIN_HASH" in
        pbkdf2:*|scrypt:*|'$2'*) : ;;
        *) echo "  Value returned doesn't look like a password hash: '$ADMIN_HASH'"
           echo "  Check what create_password_hash.py prints and adjust the capture line above."
           exit 1 ;;
    esac
    TO_SET+=("AUTHSTRIKE_ADMIN_PASSWORD_HASH=$ADMIN_HASH")
fi

if ((${#TO_SET[@]})); then
    echo "  applying ${#TO_SET[@]} change(s) (this restarts the app)..."
    az webapp config appsettings set \
        --resource-group "$RESOURCE_GROUP" \
        --name "$WEBAPP_NAME" \
        --settings "${TO_SET[@]}" \
        -o none
    SETTINGS_CHANGED=true
else
    echo "  all correct; skipping (no restart)."
fi

echo
echo "Cleaning old package..."
rm -f "$ZIP_FILE"

echo
echo "Creating deployment package..."
zip -r "$ZIP_FILE" . \
    -x ".git/*" \
    -x ".venv/*" \
    -x "__pycache__/*" \
    -x "*/__pycache__/*" \
    -x "*.pyc" \
    -x "*.pyo" \
    -x "*.md" \
    -x "Docker/*" \
    -x "runtime/*" \
    -x ".env" \
    -x "devicecode_history.json" \
    -x "token_cache.bin" \
    -x "token_history.json" \
    -x "request_counter.json" \
    -x "$ZIP_FILE"

# Give Azure time to settle before deploying, so we don't POST into a restart.
if $NEED_BUILD_WAIT; then
    echo
    echo "First-time build flag set; waiting 45s for the build service (once per app)..."
    sleep 45
elif $SETTINGS_CHANGED; then
    echo
    echo "Settings changed; waiting 15s for Kudu to settle before deploy..."
    sleep 15
fi

echo
echo "Deploying AuthStrike to Azure App Service..."
tries=3
for ((i=1; i<=tries; i++)); do
    if az webapp deploy \
        --resource-group "$RESOURCE_GROUP" \
        --name "$WEBAPP_NAME" \
        --src-path "$ZIP_FILE" \
        --type zip; then
        break
    fi
    if (( i == tries )); then
        echo "Deploy failed after $tries attempts."
        echo "Check: az webapp log deployment show -n $WEBAPP_NAME -g $RESOURCE_GROUP"
        exit 1
    fi
    echo "Deploy attempt $i failed (Kudu cycling / connection dropped); retrying in 30s..."
    sleep 30
done

echo
echo "Waiting for the app to become healthy (build + cold start can take a few min)..."
DEADLINE=$((SECONDS + 300))
until code=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 10 "$URL") && [[ $code =~ ^[23] ]]; do
    if (( SECONDS >= DEADLINE )); then
        echo "App did not become healthy within timeout."
        echo "Inspect: az webapp log tail -g $RESOURCE_GROUP -n $WEBAPP_NAME"
        exit 1
    fi
    echo "  not ready yet (last: ${code:-no response}); retrying in 10s..."
    sleep 10
done

echo
echo "Deployment successful (HTTP $code)."
echo "Application live at: $URL"
