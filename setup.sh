#!/usr/bin/env bash
# One-shot setup for the whole project. Safe to run again.
#
# Works on Linux, macOS and Windows (run it in Git Bash, which comes with Git for Windows).
#
#   1. Fill in LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in analyzer-agent-harness/.env
#      (run this script once to create the file from .env.example).
#   2. ./setup.sh
#
# Everything else is automatic: signing secret, free ports, SonarQube token, Docker stack,
# your user token, and building + installing the VS Code extension.
#
# Options (environment variables):
#   HARNESS_USER=alice          user id for the token (default: your login name)
#   NEW_TOKEN=1                 replace that user's token even if one exists
#   SONAR_ADMIN_PASSWORD=...    if you already changed SonarQube's admin password
set -euo pipefail

case $(uname -s) in
  MINGW* | MSYS* | CYGWIN*) WINDOWS=1 ;;
  *) WINDOWS= ;;
esac
if [[ $WINDOWS ]]; then
  # Git Bash rewrites arguments that look like /paths (e.g. in `docker compose exec`), so turn that
  # off and use Windows-style paths (C:/...) for the files Python opens.
  export MSYS_NO_PATHCONV=1
  ROOT=$(cd "$(dirname "$0")" && pwd -W)
else
  ROOT=$(cd "$(dirname "$0")" && pwd)
fi
H=$ROOT/analyzer-agent-harness
EXT=$ROOT/vscode-extension
ENV_FILE=$H/.env
USER_ID=$(printf %s "${HARNESS_USER:-$(whoami)}" | tr -cd 'A-Za-z0-9_.-')
[[ -n $USER_ID ]] || USER_ID=user
SONAR_ADMIN_PASSWORD=${SONAR_ADMIN_PASSWORD:-admin}

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 is not installed"; }

# Python 3: `python3` on Linux and macOS; on Windows often `python` or `py -3`
# (Windows' `python3` can be a stub that only opens the Microsoft Store, so test that it runs).
PY=()
for c in "python3" "python" "py -3"; do
  read -ra try <<< "$c"
  if command -v "${try[0]}" >/dev/null && "${try[@]}" -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
    PY=("${try[@]}"); break
  fi
done
pyrun() { [[ ${#PY[@]} -gt 0 ]] || die "Python 3.8 or newer is not installed"; "${PY[@]}" "$@"; }

# \r is dropped in case .env was saved with Windows line endings.
getenv() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '\r' || true; }
# Value comes through the environment so secrets never appear in `ps`.
setenv() {
  KEY=$1 VALUE=$2 pyrun - "$ENV_FILE" <<'EOF'
import os, sys
path, key, value = sys.argv[1], os.environ["KEY"], os.environ["VALUE"]
lines = open(path).read().splitlines()
for i, line in enumerate(lines):
    if line.startswith(key + "="):
        lines[i] = f"{key}={value}"
        break
else:
    lines.append(f"{key}={value}")
open(path, "w", newline="\n").write("\n".join(lines) + "\n")
EOF
}

port_in_use() {
  pyrun -c '
import socket, sys
s = socket.socket()
try: s.bind(("0.0.0.0", int(sys.argv[1])))
except OSError: sys.exit(0)
sys.exit(1)' "$1"
}
free_port() { local p=$1; while port_in_use "$p"; do p=$((p + 1)); done; echo "$p"; }
# Host port of a running service of this stack, or empty.
current_port() { docker compose port "$1" "$2" 2>/dev/null | awk -F: 'NF {print $NF}' || true; }

wait_for() { # url, grep pattern, seconds
  local i
  for ((i = 0; i < $3; i += 5)); do
    curl -s -m 3 "$1" 2>/dev/null | grep -q "$2" && return 0
    sleep 5
  done
  return 1
}

# --- prerequisites -----------------------------------------------------------
say "Checking prerequisites"
need docker; need curl; need npm; need npx; pyrun -c pass
docker info >/dev/null 2>&1 || die "Docker is not running (or you lack permission to use it)"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"

if [[ $(uname) == Linux ]]; then
  if (( $(sysctl -n vm.max_map_count) < 262144 )); then
    say "SonarQube needs vm.max_map_count >= 262144 (asking sudo)"
    sudo sysctl -w vm.max_map_count=262144
  fi
fi

# --- .env --------------------------------------------------------------------
cd "$H"
if [[ ! -f $ENV_FILE ]]; then
  cp .env.example "$ENV_FILE"
  die "Created $ENV_FILE. Fill in LLM_BASE_URL, LLM_API_KEY and LLM_MODEL, then run this again."
fi

LLM_BASE_URL=$(getenv LLM_BASE_URL); LLM_MODEL=$(getenv LLM_MODEL)
[[ -n $LLM_BASE_URL ]] || die "Set LLM_BASE_URL in $ENV_FILE"
[[ -n $(getenv LLM_API_KEY) ]] || die "Set LLM_API_KEY in $ENV_FILE (any text if your server needs none)"
[[ -n $LLM_MODEL && $LLM_MODEL != *your-model-name* ]] || die "Set LLM_MODEL in $ENV_FILE"
[[ $LLM_MODEL == */* ]] || die "LLM_MODEL needs a provider prefix, e.g. openai/$LLM_MODEL"

SECRET=$(getenv HARNESS_SIGNING_SECRET)
if [[ ${#SECRET} -lt 32 || $SECRET == change-me* ]]; then
  say "Generating HARNESS_SIGNING_SECRET"
  setenv HARNESS_SIGNING_SECRET "$(pyrun -c 'import secrets; print(secrets.token_hex(32))')"
fi

SX=$(getenv SEARXNG_SECRET)
if [[ ${#SX} -lt 32 ]]; then
  say "Generating SEARXNG_SECRET (web search for the agents)"
  setenv SEARXNG_SECRET "$(pyrun -c 'import secrets; print(secrets.token_hex(32))')"
fi

# --- ports -------------------------------------------------------------------
say "Choosing ports"
HP=$(current_port harness 8080); [[ -n $HP ]] || HP=$(free_port 8080)
SP=$(current_port sonarqube 9000); [[ -n $SP ]] || SP=$(free_port 9000)
if [[ $HP == 8080 && $SP == 9000 ]]; then
  rm -f docker-compose.override.yml
else
  cat > docker-compose.override.yml <<EOF
# Written by setup.sh: the default ports were taken on this machine.
services:
  harness:
    ports: !override
      - "$HP:8080"
  sonarqube:
    ports: !override
      - "$SP:9000"
EOF
fi
SCHEME=http; [[ -n $(getenv HARNESS_TLS_CERT) ]] && SCHEME=https
HARNESS_URL=$SCHEME://localhost:$HP
SONAR_URL=http://localhost:$SP
setenv HARNESS_PUBLIC_URL "$HARNESS_URL"
echo "harness: $HARNESS_URL   sonarqube: $SONAR_URL"

# --- SonarQube ---------------------------------------------------------------
say "Starting SonarQube (first start takes 1-3 minutes)"
docker compose up -d sonarqube sonar-db
wait_for "$SONAR_URL/api/system/status" '"status":"UP"' 300 || die "SonarQube did not start; see: docker compose logs sonarqube"

sonar_ok() { [[ $(curl -s -o /dev/null -w '%{http_code}' -u "$1:" "$SONAR_URL/api/projects/search") == 200 ]]; }
if sonar_ok "$(getenv SONAR_TOKEN)"; then
  echo "SONAR_TOKEN is valid"
else
  say "Creating a SonarQube token"
  T=$(curl -s -u "admin:$SONAR_ADMIN_PASSWORD" -X POST "$SONAR_URL/api/user_tokens/generate" \
        -d "name=harness-$(date +%s)" -d type=USER_TOKEN \
      | pyrun -c 'import sys, json; print(json.load(sys.stdin).get("token", ""))' 2>/dev/null || true)
  [[ -n $T ]] && sonar_ok "$T" ||
    die "Could not create a SonarQube token. If you changed the admin password, run: SONAR_ADMIN_PASSWORD='...' $0"
  setenv SONAR_TOKEN "$T"
  echo "SONAR_TOKEN written to .env"
fi

# --- harness -----------------------------------------------------------------
say "Building and starting the harness (first build takes several minutes)"
docker compose up -d --build
wait_for "$HARNESS_URL/health" '"ok"' 120 || die "Harness did not become healthy; see: docker compose logs harness"

say "Checking the LLM from inside the container"
docker compose exec -T harness python -c '
import os, json, urllib.request
base, model = os.environ["LLM_BASE_URL"].rstrip("/"), os.environ["LLM_MODEL"].split("/", 1)[1]
req = urllib.request.Request(base + "/models", headers={"Authorization": "Bearer " + os.environ["LLM_API_KEY"]})
ids = [m["id"] for m in json.load(urllib.request.urlopen(req, timeout=10))["data"]]
print("LLM reachable;", "model found" if model in ids else f"model {model!r} not listed (fine if your server uses aliases); it lists {len(ids)} models, e.g. {ids[:5]}")
' || warn "The harness cannot reach the LLM at $LLM_BASE_URL. Scans still run, but findings will not be reviewed."

# --- user token --------------------------------------------------------------
HAS_USER=$(docker compose exec -T harness python -c '
import json, os, sys
try: users = json.load(open(os.environ["HARNESS_TOKENS_FILE"]))["users"]
except FileNotFoundError: users = []
print(any(u["user_id"] == sys.argv[1] for u in users))' "$USER_ID" | tr -d '\r')
TOKEN=
if [[ $HAS_USER == True* && ${NEW_TOKEN:-} != 1 ]]; then
  echo "User '$USER_ID' already has a token (NEW_TOKEN=1 to replace it)"
else
  say "Creating a token for user '$USER_ID'"
  TOKEN=$(docker compose exec -T harness harness-token "$USER_ID" | tr -d '\r\n')
fi

# --- extension ---------------------------------------------------------------
say "Building the VS Code extension"
cd "$EXT"
npm ci --no-audit --no-fund --loglevel=error
npm run build --silent >/dev/null 2>&1
npx -y @vscode/vsce package --allow-missing-repository --skip-license -o vuln-scanner.vsix >/dev/null
echo "Packaged $EXT/vuln-scanner.vsix"

if command -v code >/dev/null; then
  say "Installing the extension and configuring VS Code"
  code --install-extension vuln-scanner.vsix --force >/dev/null 2>&1
  case $(uname -s) in
    Darwin) SETTINGS="$HOME/Library/Application Support/Code/User/settings.json" ;;
    MINGW* | MSYS* | CYGWIN*) SETTINGS="${APPDATA//\\//}/Code/User/settings.json" ;;
    *) SETTINGS="${XDG_CONFIG_HOME:-$HOME/.config}/Code/User/settings.json" ;;
  esac
  # The extension moves vulnScanner.token into secure storage on start and clears the setting.
  if URL=$HARNESS_URL TOKEN=$TOKEN pyrun - "$SETTINGS" <<'EOF'
import json, os, sys
path = sys.argv[1]
os.makedirs(os.path.dirname(path), exist_ok=True)
try:
    s = json.load(open(path, encoding="utf-8-sig")) if os.path.getsize(path) else {}
except FileNotFoundError:
    s = {}
except ValueError:
    sys.exit(1)  # settings.json has comments or trailing commas; leave it alone
s["vulnScanner.serverUrl"] = os.environ["URL"]
if os.environ["TOKEN"]:
    s["vulnScanner.token"] = os.environ["TOKEN"]
json.dump(s, open(path, "w", encoding="utf-8"), indent=4)
EOF
  then
    TOKEN=  # delivered through settings; don't print it
    echo "VS Code settings updated"
  else
    warn "Could not edit $SETTINGS automatically. Set vulnScanner.serverUrl to $HARNESS_URL yourself."
  fi
else
  warn "'code' is not on PATH. Install $EXT/vuln-scanner.vsix from VS Code (Extensions → … → Install from VSIX)."
fi

# --- summary -----------------------------------------------------------------
say "Done"
echo "Harness:   $HARNESS_URL"
echo "SonarQube: $SONAR_URL  (change the default admin/admin password there)"
if [[ -n $TOKEN ]]; then
  echo
  echo "Your token (shown once). In VS Code run 'Vuln Scanner: Set Token' and paste it:"
  echo "  $TOKEN"
fi
echo
echo "Reload VS Code (Developer: Reload Window), open the Vuln Scanner view and type: scan this project"
