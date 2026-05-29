# QChain VPS Deployment Guide

Step-by-step instructions for deploying QChain on a fresh Ubuntu VPS.
Covers exact version requirements for Rust, Python, and all dependencies.

---

## Version requirements (read this first)

The qstark_py Rust extension uses **PyO3 0.20.3**, which has strict
version constraints. Using the wrong Rust or Python version is the
most common deployment failure.

| Dependency | Required version | Why |
|------------|-----------------|-----|
| **Ubuntu** | 22.04 or 24.04 LTS | Ships Python 3.10 / 3.12 |
| **Python** | 3.10 – 3.12 only | PyO3 0.20.3 rejects Python 3.13+ |
| **Rust** | 1.75.0 – 1.77.2 | Edition 2021 needs ≥1.56; PyO3 0.20.3 breaks on ≥1.80 |
| **maturin** | 1.4 – 1.7 | Builds the PyO3 wheel |
| **VM** | 4 GB RAM, 2 CPU | 3 nodes + auto-miner + Rust compilation |

> **Common failures:**
> - `rustup` installs latest stable (1.85+) → PyO3 0.20.3 fails with
>   `unsafe extern` errors. Fix: pin to 1.77.2.
> - Ubuntu 24.10+ ships Python 3.13 → PyO3 0.20.3 refuses to build.
>   Fix: use Ubuntu 24.04 LTS (Python 3.12).
> - Missing `python3-dev` → PyO3 can't find `Python.h`.

---

## Step 0 — SSH into a fresh Ubuntu VM

```bash
ssh root@YOUR_VM_IP
```

Tested on: Hetzner CPX21, DigitalOcean Basic 4GB, Vultr 4GB.

---

## Step 1 — System packages

```bash
apt-get update && apt-get upgrade -y
apt-get install -y \
    python3 python3-pip python3-venv python3-dev \
    build-essential pkg-config libssl-dev \
    git curl ufw
```

Verify Python is 3.10–3.12:

```bash
python3 --version
# Must show 3.10.x, 3.11.x, or 3.12.x
# If it shows 3.13+, use Ubuntu 24.04 LTS instead
```

---

## Step 2 — Install Rust (pinned to 1.77.2)

Do NOT run the default `rustup` installer — it pulls the latest stable
Rust, which is too new for PyO3 0.20.3.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain 1.77.2

source "$HOME/.cargo/env"
```

Verify:

```bash
rustc --version
# Must show: rustc 1.77.2
cargo --version
```

> **Why 1.77.2?** PyO3 0.20.3 was released before Rust 1.78, which
> changed `unsafe extern` block semantics. Rust 1.80+ breaks PyO3
> 0.20.3 compilation with errors like:
> ```
> error: `unsafe extern` blocks are not supported
> ```
> Rust 1.77.2 is the last stable release before these breaking changes.

---

## Step 3 — Create service user and clone

```bash
adduser --system --group --home /opt/qchain --shell /bin/bash qchain

sudo -u qchain git clone https://github.com/sildl/qchain.git /opt/qchain
cd /opt/qchain
```

---

## Step 4 — Install Python dependencies

```bash
pip3 install --break-system-packages -r requirements.txt
```

If `requirements.txt` is missing or you want to install manually:

```bash
pip3 install --break-system-packages \
    fastapi 'uvicorn[standard]' pydantic websockets \
    pqcrypto ecdsa \
    cryptography argon2-cffi \
    qiskit qiskit-aer
```

---

## Step 5 — Build the qstark Rust extension

This is the step that fails if Rust or Python versions are wrong.

```bash
pip3 install --break-system-packages 'maturin>=1.4,<2.0'

cd /opt/qchain/qstark_py
maturin build --release
```

If it succeeds, you'll see a `.whl` file in `target/wheels/`. Install it:

```bash
pip3 install --break-system-packages --force-reinstall \
    target/wheels/qstark_py-*.whl
```

Verify the extension loads:

```bash
python3 -c "import qstark_py as q; print('field modulus:', q.field_modulus()); print('merkle depth:', q.m86_merkle_depth())"
# Should print:
#   field modulus: 18446744069414584321
#   merkle depth: 8
```

### Troubleshooting build failures

**Error: `the configured Python interpreter version (3.13) is newer than PyO3's maximum supported version (3.12)`**

Your system Python is too new. Options:
- Use Ubuntu 24.04 LTS (ships Python 3.12)
- Or install Python 3.12 via deadsnakes PPA:
  ```bash
  add-apt-repository ppa:deadsnakes/ppa -y
  apt-get install python3.12 python3.12-dev python3.12-venv
  ```
  Then point maturin at it:
  ```bash
  maturin build --release -i python3.12
  ```

**Error: `unsafe extern blocks are not supported` or other Rust compile errors**

Your Rust is too new. Fix:
```bash
rustup default 1.77.2
rustc --version   # verify: 1.77.2
cd /opt/qchain/qstark_py
cargo clean
maturin build --release
```

**Error: `Python.h: No such file or directory`**

Missing Python dev headers:
```bash
apt-get install python3-dev
```

**Error: `failed to run custom build command for 'pqcrypto-internals'`**

The pqcrypto crate needs a C compiler and cmake:
```bash
apt-get install build-essential cmake
```

---

## Step 6 — Run the smoke test

```bash
cd /opt/qchain
sudo -u qchain python3 -m pytest qchain/tests/test_chain.py \
    qchain/tests/test_shield_tx.py -q --timeout=30
```

You should see all tests pass. For the full test suite (takes longer):

```bash
sudo -u qchain python3 -m pytest qchain/tests/ -q --timeout=60 \
    --ignore=qchain/tests/test_network.py
```

---

## Step 7 — Set up the environment file

```bash
mkdir -p /etc/qchain /var/lib/qchain
chown root:qchain /etc/qchain
chmod 750 /etc/qchain
chown qchain:qchain /var/lib/qchain

# Generate a real auth token
TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Create the env file (the template in deploy/env/ may be missing
# from your clone because .gitignore previously excluded it)
cat > /etc/qchain/qchain.env << EOF
QCHAIN_DASHBOARD_TOKEN=$TOKEN
QCHAIN_DASHBOARD_BIND=0.0.0.0
QCHAIN_DASHBOARD_PORT=8101
QCHAIN_NODE_1_PORT=19101
QCHAIN_NODE_2_PORT=19102
QCHAIN_NODE_3_PORT=19103
QCHAIN_NODE_2_HTTP_PORT=8102
QCHAIN_NODE_3_HTTP_PORT=8103
QCHAIN_AUTOMINE_INTERVAL=15
QCHAIN_USER=qchain
EOF

chown root:qchain /etc/qchain/qchain.env
chmod 640 /etc/qchain/qchain.env

# Print the token — save this for the reviewer
echo ""
echo "=========================================="
echo "  DASHBOARD TOKEN (save this!):"
echo "  $TOKEN"
echo "=========================================="
echo ""
```

---

## Step 8 — Install and start systemd services

```bash
cp /opt/qchain/deploy/systemd/qchain-*.service /etc/systemd/system/
systemctl daemon-reload

systemctl enable qchain-node-1 qchain-node-2 qchain-node-3 qchain-automine

# Start in order (node-1 must be up before followers connect)
systemctl start qchain-node-1
sleep 3
systemctl start qchain-node-2
sleep 2
systemctl start qchain-node-3
sleep 2
systemctl start qchain-automine
```

Each node creates a persistent wallet on first start at
`/var/lib/qchain/node-N.wallet.json`. The wallet is auto-saved after
every mined block, so balance and shielded notes survive restarts.
You can verify wallet files exist:

```bash
ls -la /var/lib/qchain/*.wallet.json
```

---

## Step 9 — Configure firewall

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp        # SSH
ufw allow 8101/tcp      # Public dashboard
ufw enable
ufw status verbose
```

---

## Step 10 — Verify

```bash
# Check all services are running
systemctl status qchain-node-1 qchain-node-2 qchain-node-3 qchain-automine

# Check the chain is alive
TOKEN=$(grep QCHAIN_DASHBOARD_TOKEN /etc/qchain/qchain.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8101/api/state | python3 -m json.tool | head -20

# Watch the auto-miner
journalctl -u qchain-automine -f
```

From your laptop, open:

```
http://YOUR_VM_IP:8101/?token=YOUR_TOKEN
```

---

## Operations

### Restart everything

```bash
systemctl stop qchain-automine
systemctl restart qchain-node-1 qchain-node-2 qchain-node-3
sleep 3
systemctl start qchain-automine
```

### View logs

```bash
journalctl -u qchain-node-1 -f --since "5 min ago"
journalctl -u 'qchain-*' -f
```

### Update code

```bash
cd /opt/qchain
sudo -u qchain git pull
systemctl restart qchain-node-1 qchain-node-2 qchain-node-3 qchain-automine
```

### Rotate dashboard token

```bash
NEW=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
sed -i "s/^QCHAIN_DASHBOARD_TOKEN=.*/QCHAIN_DASHBOARD_TOKEN=$NEW/" /etc/qchain/qchain.env
systemctl restart qchain-node-1 qchain-node-2 qchain-node-3 qchain-automine
echo "New token: $NEW"
```

---

## Quick reference: what goes wrong and how to fix it

| Symptom | Cause | Fix |
|---------|-------|-----|
| `maturin build` fails with `unsafe extern` | Rust too new (≥1.80) | `rustup default 1.77.2` then rebuild |
| `maturin build` fails with `Python 3.13 is newer than maximum` | Python too new | Use Ubuntu 24.04 LTS (Python 3.12) |
| `maturin build` fails with `Python.h not found` | Missing dev headers | `apt install python3-dev` |
| `pqcrypto` build fails | Missing C toolchain | `apt install build-essential cmake` |
| Dashboard shows blank page | Auth token not passed to frontend | Update to fixed `server.py` (see bug fixes) |
| Dashboard shows 401 on every API call | Token not in URL | Open `http://IP:8101/?token=YOUR_TOKEN` |
| Node crashes with `ModuleNotFoundError` | Missing Python dep | Re-run `pip install -r requirements.txt` |
| High memory / swapping | Qiskit loaded at startup (old bug) | Update to fixed `qrng.py` with lazy imports |
| Chain gets slow after hours | `balance_of` replay (old bug) | Update to fixed `blockchain.py` with cache |
| Auto-miner shows `FAIL: HTTP 401` | Token mismatch | Rotate token (see Operations above) |
| `cp: cannot stat 'deploy/env/qchain.env.example'` | `.gitignore` excluded `deploy/env/` | Update `.gitignore` (add `!deploy/env/`), or use Step 7 above which creates the file inline |
| Balance resets to 0 after restart | No `--wallet` flag (old version) | Update systemd services from the fixed zip; restart all nodes |
| `node-1.wallet.json` not created | `/var/lib/qchain` doesn't exist or wrong permissions | `mkdir -p /var/lib/qchain && chown qchain:qchain /var/lib/qchain` |
