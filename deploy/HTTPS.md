# HTTPS and authentication on the local network

This is an optional configuration for access from other devices. For individual
use on the same computer, use the loopback HTTP setup in [README.md](README.md).

The local network entry point uses Uvicorn's native TLS. Every HTTP route,
including the browser interface, static assets, health endpoint and API docs,
requires HTTP Basic authentication once `CYBER_RSS_AUTH_FILE` is configured.
Passwords are stored as salted scrypt hashes; comparisons use constant-time
operations. Cleartext requests never receive a password challenge. The API
refuses to start a non-loopback listener without both authentication and TLS.
Forwarded headers are disabled: clients cannot invent an IP address to obtain
a fresh rate allowance or claim that a cleartext request used HTTPS.

## Prepare and activate

Include every name/IP clients will use in the certificate. Example for this
Windows/WSL installation (substitute current addresses when necessary):

```bash
.venv/bin/python deploy/configure_https.py \
  --names localhost DESKTOP-INHUMK2 127.0.0.1 172.21.19.251 192.168.1.11
```

This creates a local CA and a one-year server certificate under
`deploy/generated/https/`, along with `credentials.json`, `.env.https`, a private
`access.txt` containing the generated login, and a reviewable `https.conf` systemd
override. The directory is mode `0700`; key and credential files are mode `0600`
and ignored by Git. No secrets are printed or added to tracked configuration.
The existing archive, worker and backup configuration are retained.

Review the override, then install and activate it:

```bash
.venv/bin/python deploy/configure_https.py \
  --names localhost DESKTOP-INHUMK2 127.0.0.1 172.21.19.251 192.168.1.11 --install
systemctl --user daemon-reload
systemctl --user restart cyber-rss-api.service
```

The API now listens on port 8443 using **HTTPS**. This port was verified from
the Windows host; port 8000 was resetting Windows TLS connections in this environment. The old HTTP URL on port 8000 will not work.
The default listener is IPv4 `0.0.0.0`; it remains protected by TLS and
authentication on every interface. Use `--listen PRIVATE_IP` on a machine with
a stable address to bind only that interface. Do not create router forwarding
or internet firewall rules for this LAN configuration.

## Trust and sign in

Copy **only `ca.crt`** to each client through a trusted channel. On Windows,
import it into the current user's *Trusted Root Certification Authorities*
store, or run:

```powershell
certutil -user -addstore Root C:\path\to\ca.crt
```

Open `https://192.168.1.11:8443` (or a configured hostname) and enter the username
and password from `deploy/generated/https/access.txt`. Browser authentication
dialogs handle the login; the frontend does not store a password in JavaScript
or local storage. Basic authentication is a single shared reader account with
no roles, session management or logout endpoint. Close the browser session or
clear saved credentials to sign out. The initial account is named `reader`.

To verify with a client that trusts only this CA:

```bash
curl --cacert deploy/generated/https/ca.crt --user reader https://127.0.0.1:8443/health
```

Curl prompts for the password. Do not put passwords in command-line arguments,
URLs, logs or committed files. `ca.key` and `server.key` stay on the server;
clients only need the public `ca.crt`. Protect the CA private key: anyone with
it can issue certificates trusted by these clients.

For Windows `curl.exe`, add `--ssl-revoke-best-effort` when validating this
local CA with `--cacert`. The local certificates have no online revocation
endpoint; this option tolerates missing revocation information while retaining
the certificate chain and hostname checks. Do not use `--insecure`.
See [curl's Schannel revocation option](https://curl.se/docs/manpage.html#--ssl-revoke-best-effort).

## WSL2 network forwarding

The current installation runs inside WSL2. Its address `172.21.19.251` is not
the Windows LAN address (`192.168.1.11`); other LAN devices need a Windows
forwarding rule. Run the prepared script in **Windows PowerShell as
Administrator**, using the actual Windows path to this repository:

```powershell
& '\\wsl.localhost\Ubuntu-24.04\home\lasgota\code\cyber-rss-reader\deploy\enable_lan_access.ps1' `
  -LanAddress 192.168.1.11 -WslAddress 172.21.19.251 -Port 8443
```

If using a different distribution, find its name with `wsl -l -q`. The script creates a TCP port proxy
bound specifically to the Windows private LAN IP, and a firewall allow rule
with `RemoteAddress LocalSubnet`. It validates private addresses and preserves
unrelated forwarding/firewall rules. Windows administrator rights are required;
Linux/sandbox elevation does not grant them. The script is intended for the
WSL2 NAT networking mode; native Linux hosts do not need this forwarding step.
Test the HTTPS URL from another LAN device after activation.

WSL's IP can change after restart; obtain it with `wsl hostname -I` and rerun
the script with the current private address. Reserve the Windows LAN IP in
DHCP, or renew the certificate if that address changes. If access disappears
after reboot, check both the Linux service and the Windows forwarding target.

To remove these Windows rules (Administrator PowerShell), use the matching
cleanup script, which checks ownership before changing the rules:

```powershell
& '\\wsl.localhost\Ubuntu-24.04\home\lasgota\code\cyber-rss-reader\deploy\disable_lan_access.ps1' `
  -LanAddress 192.168.1.11 -WslAddress 172.21.19.251 -Port 8443
```

## Limits and maintenance

The default token budgets allow 120 requests/minute per source IP, with an
initial burst of 30, and 600/minute globally, with a burst of 60. Failed logins,
assets and health checks also consume tokens. A rejected request returns
HTTP 429 with `Retry-After`. Requests are stopped before password hashing,
search or topic extraction. Idle client buckets expire; active client tracking
is bounded at 10,000 entries. Uvicorn also caps concurrent connections/tasks at
32. Clients behind the same NAT share an IP allowance. The Windows TCP port
proxy presents forwarded clients to WSL using the Windows gateway IP, so LAN
clients accessing this forwarding rule share that per-IP allowance.

Edit `.env.https` to tune `CYBER_RSS_RATE_PER_MINUTE`, `CYBER_RSS_RATE_BURST`,
`CYBER_RSS_RATE_GLOBAL_PER_MINUTE` and `CYBER_RSS_RATE_GLOBAL_BURST`, then restart
the API. Budgets live in one process and reset on restart; keep one worker.
Multiple replicas would require a shared limiter. Rerunning the setup script
regenerates `.env.https` with the default limits.

Check expiry and renew **before the one-year server certificate expires**:

```bash
openssl x509 -in deploy/generated/https/server.crt -noout -enddate
.venv/bin/python deploy/configure_https.py \
  --names localhost DESKTOP-INHUMK2 127.0.0.1 172.21.19.251 192.168.1.11 --renew
systemctl --user restart cyber-rss-api.service
```

Renewal preserves the existing CA and login, so clients keep their trust. The
CA expires after ten years; distribute a new CA before that date. Certificate
renewal is manual. Back up the CA/keys separately in protected storage if this
identity must survive server loss; article snapshots do not contain secrets.

To rotate the password, create a new credential record using
`web_api.security.create_credentials` (a password of at least 16 characters is
required), atomically replace the mode `0600` `credentials.json`, update your
protected password record and restart the API. A missing, malformed or insecurely
permissioned configured credential file prevents startup; it does not disable
authentication. To return to loopback HTTP, remove only the installed
`cyber-rss-api.service.d/https.conf` override, reload systemd and restart the API;
also remove the Windows forwarding rule before disabling authentication.

Implementation references: [Python scrypt](https://docs.python.org/3.12/library/hashlib.html#hashlib.scrypt),
[HTTP Basic authentication](https://fastapi.tiangolo.com/advanced/security/http-basic-auth/),
[Uvicorn TLS and connection limits](https://uvicorn.dev/settings/),
and [Microsoft WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking).
