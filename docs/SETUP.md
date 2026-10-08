# Setup guide

How to run the scanner harness in Docker, connect an LLM and SonarQube, and install the VS Code extension. The steps take about 15 minutes, most of it waiting for Docker images and SonarQube to start.

## Quick way: `setup.sh`

```sh
./setup.sh                                  # first run creates analyzer-agent-harness/.env and stops
# fill in LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in that file
./setup.sh                                  # does everything else
```

It works on Linux, macOS and Windows. On Windows, run it in **Git Bash** (part of [Git for Windows](https://git-scm.com/download/win)), not PowerShell or cmd. It finds Python as `python3`, `python` or `py -3`, and writes VS Code's settings in the right place for each system.

The script generates the signing secret and the SearXNG secret (for the agents' web search), picks free ports, writing an override file if 8080 or 9000 are taken. It starts SonarQube and creates its token, builds and starts the harness, and checks the LLM. It then creates your user token, and builds and installs the extension with the server URL and token set in VS Code. It is safe to run again: it keeps a valid SonarQube token and an existing user token.

Options: `HARNESS_USER=alice` (default: your login name), `NEW_TOKEN=1` (replace your token), `SONAR_ADMIN_PASSWORD=...` (if you changed SonarQube's admin password). On Linux it may ask for `sudo` to raise `vm.max_map_count`.

The rest of this guide is the same setup done by hand.

## What you need

- Docker with Compose v2
- Node.js 20 or later and npm (to build the extension)
- VS Code with the `code` command on your `PATH`
- An OpenAI-compatible LLM server reachable from Docker, for example LM Studio, Ollama or vLLM serving a `/v1` API
- Linux only: `vm.max_map_count` of at least 262144, which SonarQube needs:
  ```sh
  sudo sysctl -w vm.max_map_count=262144
  ```

## 1. Configure the harness

```sh
cd analyzer-agent-harness
cp .env.example .env
```

Fill in `.env`:

| Variable | What to put | Example |
| --- | --- | --- |
| `HARNESS_PUBLIC_URL` | The URL VS Code uses to reach the harness. Upload links are built from it, so the host port must match. | `http://localhost:8080` |
| `HARNESS_SIGNING_SECRET` | A long random string that signs upload links. Never keep the placeholder. | `openssl rand -hex 32` |
| `LLM_BASE_URL` | Your LLM server's `/v1` URL, as seen from inside the container. For a server on the Docker host, use `host.docker.internal` (the compose file maps it on Linux too). | `http://192.168.1.20:9302/v1` |
| `LLM_API_KEY` | The server's key, or any text if it needs none | `not-needed` |
| `LLM_MODEL` | `openai/` followed by the model id the server lists | `openai/deephat-v1-7b` |
| `SONAR_TOKEN` | Leave empty for now. You create it in step 3. | |

To generate the signing secret straight into the file:

```sh
sed -i "s#^HARNESS_SIGNING_SECRET=.*#HARNESS_SIGNING_SECRET=$(openssl rand -hex 32)#" .env
```

To check the model id, run `curl <LLM_BASE_URL>/models` and use one of the `id` values.

Optional settings, such as `LLM_MAX_PARALLEL`, `LLM_TIMEOUT_SECONDS` and `UPLOAD_MAX_MB`, are listed with their defaults in [IMPLEMENT_HARNESS.md](harness/IMPLEMENT_HARNESS.md).

## 2. If ports 8080 or 9000 are already in use

The compose file publishes the harness on 8080 and SonarQube on 9000. To see what is using them:

```sh
docker ps --format '{{.Names}}\t{{.Ports}}' | grep -E ':(8080|9000)->'
```

If either is taken, create `analyzer-agent-harness/docker-compose.override.yml` (it is gitignored), choosing free ports:

```yaml
services:
  harness:
    ports: !override
      - "8090:8080"
  sonarqube:
    ports: !override
      - "9010:9000"
```

Then set `HARNESS_PUBLIC_URL=http://localhost:8090` in `.env`. Compose picks up the override file on its own. The rest of this guide uses the default ports, so change them to yours as you go.

## 3. Start SonarQube and create its token

```sh
docker compose up -d sonarqube sonar-db
```

Wait until it reports `UP`, which takes 1 to 3 minutes:

```sh
curl -s http://localhost:9000/api/system/status
```

Create a **User** token. A Global Analysis token is not enough, because the harness also reads issues and deletes projects. Either:

- **Browser:** open http://localhost:9000, log in as `admin` / `admin`, set a new password, then go to *My Account → Security → Generate Tokens*, type **User**.
- **Command line,** writing the token straight into `.env` without printing it:
  ```sh
  T=$(curl -s -u admin:admin -X POST http://localhost:9000/api/user_tokens/generate \
        -d name=harness -d type=USER_TOKEN | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
  sed -i "s#^SONAR_TOKEN=.*#SONAR_TOKEN=$T#" .env
  ```
  After this, log in to the web UI once and change the default `admin` password. The token keeps working.

To check the token:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -u "$(grep ^SONAR_TOKEN= .env | cut -d= -f2-):" \
  http://localhost:9000/api/projects/search      # 200 = good, 401 = wrong token
```

A token made on a different SonarQube server does not work here: every SonarQube instance has its own users and tokens.

## 4. Start the harness

```sh
docker compose up -d --build
curl http://localhost:8080/health          # {"status":"ok"}
```

The first build takes several minutes, because it downloads Semgrep rules, Gitleaks, the SonarScanner and Node.js.

To check that the harness can reach the LLM:

```sh
docker compose exec -T harness python -c '
import os,json,urllib.request
u=os.environ["LLM_BASE_URL"].rstrip("/")+"/models"
r=urllib.request.Request(u,headers={"Authorization":"Bearer "+os.environ["LLM_API_KEY"]})
print([m["id"] for m in json.load(urllib.request.urlopen(r,timeout=10))["data"]])'
```

If this fails, the container cannot see your LLM server. Use an address the container can reach: not `localhost`, but the host's LAN IP or `host.docker.internal`.

After any change to `.env`, run `docker compose up -d harness` so the container restarts with the new settings.

## 5. Create a user token

```sh
docker compose exec harness harness-token alice --name "Alice"
```

The token is printed once. Only its hash is stored, so if you lose it, create a new one. Run the command again for each person who will use the scanner.

## 6. Install the VS Code extension

```sh
cd ../vscode-extension
npm ci
npm run build
npx @vscode/vsce package --allow-missing-repository --skip-license -o vuln-scanner.vsix
code --install-extension vuln-scanner.vsix --force
```

Run the same commands again after pulling changes to update the extension.

For extension development, open `vscode-extension/` in VS Code and press **F5** instead. That starts a separate VS Code window with the extension loaded from source.

## 7. Connect VS Code

1. Open Settings and set **`vulnScanner.serverUrl`** to the harness URL, for example `http://localhost:8080`. It must match `HARNESS_PUBLIC_URL`.
2. Run **Vuln Scanner: Set Token** from the Command Palette and paste the token from step 5. You can also paste it into the `vulnScanner.token` setting. Either way, the extension moves it into VS Code's secure storage and clears the setting.
3. Reload the window (**Developer: Reload Window**).
4. Open the **Vuln Scanner** view (the shield icon in the activity bar) and type `scan this project`.

Findings appear as each scanner finishes. The LLM then reviews them one by one: with a 7B model, expect about 15 findings a minute.

## Optional: HTTPS

```sh
cd analyzer-agent-harness
scripts/make_dev_cert.sh                     # add extra hostnames or IPs as arguments
```

Add to `.env`:

```sh
HARNESS_PUBLIC_URL=https://localhost:8080
HARNESS_TLS_CERT=/certs/dev-cert.pem
HARNESS_TLS_KEY=/certs/dev-key.pem
```

Run `docker compose up -d harness`. In VS Code, change `vulnScanner.serverUrl` to `https://…` and set `vulnScanner.caCertificate` to the full path of `analyzer-agent-harness/certs/dev-cert.pem`.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `docker compose up` fails with "port is already allocated" | Another container uses the port. See step 2. |
| SonarQube exits soon after starting (Linux) | `vm.max_map_count` is too low. See "What you need". |
| Scan finishes, but the error says `sonarqube: …` | Wrong `SONAR_TOKEN`, or SonarQube is still starting. Check the token as in step 3, then run `docker compose up -d harness`. The other scanners' findings are kept. |
| Every finding's verdict is `unsure`, or chat says "The LLM cannot be reached" | The harness cannot reach the LLM. Run the check in step 4. |
| Chat replies are odd, but scan commands still work | Small models sometimes ignore instructions. When the LLM fails, scan commands fall back to keyword matching. A larger model gives better routing and reviews. |
| Extension says "No token is set" | Run **Vuln Scanner: Set Token** again. Tokens are stored per VS Code profile. |
| Upload fails with HTTP 403 | The upload link expired or was signed with a different secret. Check that `HARNESS_PUBLIC_URL` matches the URL VS Code uses, then rescan. |
| Logs show `Invalid HTTP request received` | Something is connecting with HTTPS, or isn't sending HTTP, to a plain-HTTP harness. Check that the `vulnScanner.serverUrl` scheme matches the server. |

To see what the harness is doing:

```sh
docker compose logs -f harness
```

Logs never contain tokens, upload signatures, API keys or secret values.

## Stopping and resetting

```sh
docker compose down          # stop; sessions, findings and tokens are kept in volumes
docker compose down -v       # also delete all data, including SonarQube and user tokens
```

After `down -v`, repeat steps 3 to 5 and 7: new SonarQube token, new user tokens.
