# QChain deployment guide

Step-by-step instructions for bringing up a 3-node QChain network on
a single Linux VM using systemd. Tested target: fresh Ubuntu 22.04
or 24.04 LTS on a 4 GB / 2 CPU VM.

## What you're deploying

- **3 QChain nodes** running on one VM, peering via localhost
  (internal-only p2p — not exposed to the public internet)
- **1 public-facing dashboard** on node 1, port 8101
  (the URL the grant reviewer hits)
- **2 internal-only debug dashboards** on nodes 2 and 3
  (reachable only from inside the VM, useful for `curl` debugging)
- **1 auto-miner** that periodically triggers `POST /api/mine`
  on node 1, so the chain produces blocks every ~15 seconds

The chain is **ephemeral**: chain state lives in memory and resets
on `systemctl restart`. This is fine for a demo; production
persistence is a follow-up not in this deployment.

## Prerequisites

- A Linux VM with root access (Ubuntu 22.04/24.04 LTS recommended)
- 4 GB RAM, 2 CPU recommended (Hetzner CPX21, DO Basic 4GB, etc.)
- Outbound internet access (to clone the repo + install deps)
- Inbound TCP 22 (SSH) and TCP 8101 (dashboard) from your reviewer's
  network
- Domain name (optional — IP address works fine for the demo)

## Step 0: SSH into the VM as root

```bash
ssh root@YOUR_VM_IP
```

## Step 1: Create the unprivileged service user

The services don't need root. Create a `qchain` user and group:

```bash
adduser --system --group --home /opt/qchain --shell /bin/bash qchain
```

This creates the user without a password (system account) — root
will own everything; the qchain user just runs the services.

## Step 2: Install Python and clone the repo

```bash
apt-get update
apt-get install -y python3 python3-pip python3-venv git build-essential curl

# Clone as the qchain user
sudo -u qchain git clone https://github.com/sildl/qchain.git /opt/qchain
cd /opt/qchain
```

## Step 3: Install Python dependencies

```bash
# Install at system level so systemd can find them
pip3 install --break-system-packages -r requirements.txt
```

If `requirements.txt` doesn't exist or you prefer a virtualenv,
use this minimal approach instead:

```bash
pip3 install --break-system-packages \
    fastapi uvicorn websockets pydantic \
    cryptography argon2-cffi ecdsa qiskit
```

You will also need the qstark Rust extension built and installed.
If `pip install qchain-qstark` works for your platform, use it.
Otherwise build from source:

```bash
# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

cd /opt/qchain/qstark_py
pip3 install --break-system-packages maturin
maturin build --release
pip3 install --break-system-packages target/wheels/qchain_qstark*.whl
cd /opt/qchain
```

Verify by running the test suite (this is your "is everything
installed correctly" smoke test):

```bash
sudo -u qchain python3 -m pytest qchain/tests/ -q --timeout=30 \
    --ignore=qchain/tests/test_anon_stark.py
```

You should see 334 passed (or similar — the exact count is in the
project's README). If this fails, do not proceed; debug the install
first.

## Step 4: Create runtime directories

```bash
# Future-proof: a place for any persistent state we might add later
mkdir -p /var/lib/qchain
chown qchain:qchain /var/lib/qchain

# Config directory
mkdir -p /etc/qchain
chown root:qchain /etc/qchain
chmod 750 /etc/qchain
```

## Step 5: Set up the environment file

```bash
cp /opt/qchain/deploy/env/qchain.env.example /etc/qchain/qchain.env

# Generate a real dashboard token (don't use the placeholder)
TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
sed -i "s/REPLACE_ME_WITH_A_SECRET_TOKEN/$TOKEN/" /etc/qchain/qchain.env

# Lock down — only root and the qchain group can read
chown root:qchain /etc/qchain/qchain.env
chmod 640 /etc/qchain/qchain.env

# Print the token so you can share it with the grant reviewer
echo "Dashboard token (save this and share with the reviewer):"
grep QCHAIN_DASHBOARD_TOKEN /etc/qchain/qchain.env
```

**SAVE THE TOKEN.** You'll give it to the grant reviewer so they can
log into the dashboard. Anyone with the token can interact with the
chain (mine blocks, submit transactions).

## Step 6: Install the systemd units

```bash
cp /opt/qchain/deploy/systemd/qchain-*.service /etc/systemd/system/
systemctl daemon-reload

# Enable so they auto-start on reboot
systemctl enable qchain-node-1.service
systemctl enable qchain-node-2.service
systemctl enable qchain-node-3.service
systemctl enable qchain-automine.service
```

## Step 7: Configure the firewall

See [`firewall-setup.md`](firewall-setup.md) for the full options.
Quick version with ufw:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp        # SSH
ufw allow 8101/tcp      # Public dashboard
ufw enable
ufw status verbose
```

## Step 8: Start the services

Start in order (node-1 first so the others have something to connect to):

```bash
systemctl start qchain-node-1.service
sleep 3
systemctl start qchain-node-2.service
sleep 2
systemctl start qchain-node-3.service
sleep 2
systemctl start qchain-automine.service
```

## Step 9: Verify everything is running

```bash
# All four should be active (running)
systemctl status qchain-node-1
systemctl status qchain-node-2
systemctl status qchain-node-3
systemctl status qchain-automine

# Check the chain is alive — should see incrementing block counts
TOKEN=$(grep QCHAIN_DASHBOARD_TOKEN /etc/qchain/qchain.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8101/api/state | head

# Watch the auto-miner logs
journalctl -u qchain-automine -f
```

You should see something like:
```
[2026-05-26T14:30:01] OK: mined block #5 (1 txs) (lifetime: 5 blocks in 75s)
[2026-05-26T14:30:16] OK: mined block #6 (1 txs) (lifetime: 6 blocks in 90s)
```

## Step 10: Test from outside the VM

From your laptop (or wherever the grant reviewer is):

```bash
# The HTML dashboard
open http://YOUR_VM_IP:8101/

# An API call (token required for most endpoints)
TOKEN="<the token from step 5>"
curl -H "Authorization: Bearer $TOKEN" http://YOUR_VM_IP:8101/api/state | python3 -m json.tool
```

When you open the dashboard in a browser, it'll prompt for the
token. Paste it once; the UI remembers it for the session.

## Step 11: Share with the grant reviewer

Tell the reviewer:

> The deployed QChain is at `http://YOUR_VM_IP:8101/`. Open it in
> a browser and enter the auth token below when prompted.
>
> Token: `<the token from step 5>`
>
> Once you're in, you can see real-time chain state. The chain
> produces a block every ~15 seconds via an auto-miner. You can
> also drive activity manually (mine extra blocks, submit
> transactions, deposit/withdraw to the mixer).
>
> To run the end-to-end demo against a fresh in-memory chain (for
> reproducibility on your own machine):
>     git clone https://github.com/sildl/qchain.git
>     cd qchain
>     pip install -r requirements.txt
>     python -m qchain.demo.end_to_end

## Operations

### Restart everything

```bash
systemctl restart qchain-node-1 qchain-node-2 qchain-node-3 qchain-automine
```

Note: chain state is ephemeral. A restart wipes the chain.

### Stop everything

```bash
systemctl stop qchain-automine qchain-node-3 qchain-node-2 qchain-node-1
```

(Stop in reverse order — auto-miner first so it doesn't spam
errors during the brief moment node-1 is down.)

### View logs

```bash
# All four services
journalctl -u 'qchain-*' -f

# Just one
journalctl -u qchain-node-1 -f --since "5 minutes ago"
```

### Update to a newer version

```bash
cd /opt/qchain
sudo -u qchain git pull
systemctl restart qchain-node-1 qchain-node-2 qchain-node-3 qchain-automine
```

### Rotate the dashboard token

```bash
NEW_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
sed -i "s/^QCHAIN_DASHBOARD_TOKEN=.*/QCHAIN_DASHBOARD_TOKEN=$NEW_TOKEN/" /etc/qchain/qchain.env
systemctl restart qchain-node-1 qchain-node-2 qchain-node-3 qchain-automine
echo "New token: $NEW_TOKEN"
```

## Honest scope notes

- **No TLS.** The dashboard is HTTP-only. Anyone on the path between
  the reviewer and your VM can see the token and the chain state.
  This is fine for a demo over the open internet but is NOT what a
  production deployment would do. To add TLS later, front the
  dashboard with Caddy or nginx — see the project's open questions
  for the pattern.

- **No persistence across restarts.** The chain is in-memory. A
  `systemctl restart` resets to genesis. For the grant demo this is
  fine — the chain rebuilds quickly via auto-mining. For a longer-
  lived deployment, add `--chain-file` support to the dashboard
  (open follow-up).

- **No real peer authentication.** The p2p ports are firewalled
  from outside, but inside the VM, nodes trust each other's gossip.
  This is research-grade p2p; a malicious peer with localhost
  access (i.e., root on the VM) could poison the chain. The
  threat model documents this; see THREAT-MODEL.md.

- **Single-validator mining.** Block production is PoW with no
  difficulty adjustment, mined by node 1 (where the auto-miner
  points). Nodes 2 and 3 receive blocks via gossip and replay-
  verify them. This is fine for a demo; a production network
  would need real consensus.

## Troubleshooting

### "systemctl status qchain-node-1" shows "failed"

Check the logs:
```bash
journalctl -u qchain-node-1 --since "5 minutes ago" --no-pager
```

Common causes:
- `ModuleNotFoundError`: missing Python dep (re-run Step 3)
- Permission denied on `/opt/qchain`: ownership wrong
  (run `chown -R qchain:qchain /opt/qchain`)
- Port already in use: another process bound 8101 already
  (`ss -tlnp | grep 8101` to find it)

### The dashboard returns 401 Unauthorized

You're missing the bearer token. From the browser, append `?token=<TOKEN>`
to the URL once; the UI remembers it. From curl, pass `-H "Authorization:
Bearer <TOKEN>"`.

### The chain isn't producing blocks

Check the auto-miner:
```bash
systemctl status qchain-automine
journalctl -u qchain-automine -f
```

If it's failing with "HTTP 401", the token in `/etc/qchain/qchain.env`
doesn't match what node-1 is using. Rotate it (Operations → "Rotate
the dashboard token").

### Followers (nodes 2/3) don't appear to be peering

Check from inside the VM:
```bash
TOKEN=$(grep QCHAIN_DASHBOARD_TOKEN /etc/qchain/qchain.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8101/api/peers
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8102/api/peers
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8103/api/peers
```

You should see each node listing the others as peers. If not, the
boot order may have been wrong (followers tried to connect before
node-1 was up). Restart in order:
```bash
systemctl restart qchain-node-1
sleep 3
systemctl restart qchain-node-2 qchain-node-3
```

The followers will retry connecting to the bootstrap; nodes 2 and 3
will eventually find each other via node-1's gossip.
