# Firewall setup for QChain deployment

The deployed VM should only expose what's necessary. This document
lists the exact rules. Pick one of the three sections below depending
on your firewall tool.

## What needs to be open

| Port  | Direction | Purpose                                 | Public? |
|-------|-----------|-----------------------------------------|---------|
| 22    | inbound   | SSH for administration                  | YES (or restrict to your IP) |
| 8101  | inbound   | Public dashboard (`QCHAIN_DASHBOARD_PORT`) | YES   |
| 19101 | inbound   | Node 1 p2p (`QCHAIN_NODE_1_PORT`)       | NO    |
| 19102 | inbound   | Node 2 p2p (`QCHAIN_NODE_2_PORT`)       | NO    |
| 19103 | inbound   | Node 3 p2p (`QCHAIN_NODE_3_PORT`)       | NO    |
| 8102  | inbound   | Node 2 debug dashboard                  | NO    |
| 8103  | inbound   | Node 3 debug dashboard                  | NO    |

The p2p ports are listed in the table because the dashboard.server
CLI binds them to 0.0.0.0 in the current implementation. The
firewall is what actually keeps them internal.

## Option A: ufw (recommended for Ubuntu/Debian VMs)

```bash
# Default deny everything inbound
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (you'll be locked out otherwise)
sudo ufw allow 22/tcp

# Allow the public dashboard
sudo ufw allow 8101/tcp

# Enable
sudo ufw enable

# Verify
sudo ufw status verbose
```

You should see:
```
22/tcp                     ALLOW IN    Anywhere
8101/tcp                   ALLOW IN    Anywhere
```

Everything else (p2p ports, internal dashboards) is denied at the
firewall, even though the services bind to 0.0.0.0.

## Option B: Restrict SSH to your IP (more secure)

If you have a static IP at home/office, restrict SSH:

```bash
sudo ufw delete allow 22/tcp
sudo ufw allow from YOUR.HOME.IP.ADDRESS to any port 22 proto tcp
```

Be careful: if your IP changes, you'll be locked out. Check first:
```bash
curl ifconfig.me
```

## Option C: iptables (if ufw isn't available)

```bash
# Flush existing rules (CAREFUL: this drops all rules including SSH)
sudo iptables -F INPUT

# Allow established/related (return traffic)
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback (essential for the p2p between local nodes)
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow public dashboard
sudo iptables -A INPUT -p tcp --dport 8101 -j ACCEPT

# Default drop
sudo iptables -P INPUT DROP

# Save (Debian/Ubuntu)
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

## Verify after setup

From a different machine (your laptop), test:

```bash
# Should succeed:
curl http://VM_IP:8101/                  # Dashboard HTML
ssh qchain@VM_IP                         # SSH access

# Should FAIL (timeout or connection refused):
curl http://VM_IP:19101/                 # p2p port
curl http://VM_IP:8102/                  # internal debug dashboard
```

If the first two work and the second two fail, the firewall is
correct.

## Cloud provider firewalls

Some providers (Hetzner Cloud, DigitalOcean) have their own
"firewall" feature that operates at the network level, in addition
to the VM's local firewall. Both work; either is sufficient. Using
both is defense-in-depth.

- **Hetzner**: Cloud Console → Firewalls → New Firewall → allow
  TCP 22 and TCP 8101 inbound, attach to your VM.
- **DigitalOcean**: Networking → Firewalls → Create Firewall →
  same allow-list, attach to your Droplet.

If you use a cloud-provider firewall, you can skip the VM-local
firewall (Option A/B/C above), though running both is also fine.
