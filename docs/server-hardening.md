# Secure Your Cloud Server in 15 Steps

Reference checklist for infrastructure hardening. Mapping to Sentinel's architecture noted where applicable.

## Checklist

| # | Step | Command / Action | Sentinel Mapping |
|---|------|-----------------|-----------------|
| 01 | Never run as root | `adduser deploy && usermod -aG sudo deploy` | N/A — Cloudflare Workers are serverless |
| 02 | SSH keys only — kill passwords | `ssh-copy-id deploy@server`, `PasswordAuthentication no` in sshd_config | N/A — no SSH; Cloudflare Access JWT auth |
| 03 | Change default SSH port | `Port 2222` in sshd_config | N/A — no SSH |
| 04 | Firewall everything with UFW | `ufw default deny incoming && ufw allow 2222/tcp && ufw allow 443/tcp && ufw enable` | Cloudflare network handles this; Worker bindings are not publicly routable |
| 05 | Install Fail2Ban | `apt install fail2ban && systemctl enable fail2ban` | Cloudflare Access + rate limiting at the edge |
| 06 | Auto-update security patches | `apt install unattended-upgrades` | Container base image pinned (`sandbox:0.7.0`); update via Dockerfile rebuild |
| 07 | Force HTTPS | `certbot --nginx -d yourdomain.com` | Cloudflare enforces HTTPS by default |
| 08 | Disable root login over SSH | `PermitRootLogin no` in sshd_config | N/A — no SSH |
| 09 | VPN/Tailscale for internal services | Never expose admin panels or databases publicly | D1/KV/R2 only accessible via Worker bindings; `/_admin/` behind Cloudflare Access |
| 10 | Scan your own open ports | `nmap -sV your-server-ip` | Container exposes only port 18789 internally; no public ports |
| 11 | Isolate your database | DB only accepts connections from app's internal IP | D1/KV bound to Worker — no public endpoint; SQLite inside Durable Object |
| 12 | Set up log monitoring | `journalctl -f` at minimum | Invariant #2: all tool calls audited to D1; Cloudflare Observability MCP |
| 13 | Automate backups. Test restores. | Daily snapshots + off-site | R2 bucket (`MOLTBOT_BUCKET`) for persistence; Cloudflare manages D1 backups |
| 14 | Containerize with Docker | Each service isolated | Sandbox container isolates OpenClaw + claude-mem from the Worker |
| 15 | Monthly vulnerability scans | Trivy, OpenVAS, or Numasec | `/security-audit` skill validates 6 invariants; add Trivy to CI for container scans |
