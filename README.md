# WireGuard Manager with Bandwidth Control

Complete lifecycle management system for WireGuard VPN with quota enforcement and admin controls.

## Features
- Client lifecycle management (create/delete/list)
- Bandwidth quotas & admin exceptions
- Persistent iptables rules
- Automatic IP assignment
- Usage monitoring
- Config file management

## Installation
```bash
sudo apt update && sudo apt install -y wireguard iptables-persistent python3
chmod +x wg-manager.py
```

## Server Initialization (Run Once)
```bash
sudo ./wg-manager.py add -n 0
```

## Client Management

### Add Clients
```bash
# Add 100 regular clients (50GB quota each)
sudo ./wg-manager.py add -n 100

# Add 5 admin clients (unlimited bandwidth)
sudo ./wg-manager.py add -n 5 -p admin --admin

# Add single client with custom prefix
sudo ./wg-manager.py add -n 1 -p user123
```

### Remove Client
```bash
sudo ./wg-manager.py delete --username client001
```

### List Clients
```bash
sudo ./wg-manager.py list
```

### Monitor Usage
```bash
sudo ./wg-manager.py usage
```

## Configuration Files
Client configs are stored in `~/wireguard_clients/`. To download:
```bash
scp root@your-server:~/wireguard_clients/client001.conf .
```

## Bandwidth Management
### Reset Monthly Quota (1TB example)
```bash
sudo iptables -D FORWARD -s 10.0.0.2 -j DROP
sudo iptables -A FORWARD -s 10.0.0.2 -m quota --quota 107374182400 -j ACCEPT
sudo iptables -A FORWARD -s 10.0.0.2 -j DROP
sudo netfilter-persistent save
```

## Monitoring
### Live Traffic
```bash
sudo watch -n 1 "wg show"
```

### Bandwidth Tests
```bash
# Server
iperf3 -s

# Client
iperf3 -c SERVER_IP -P 10
```

## Service Management
```bash
# Restart WireGuard
sudo systemctl restart wg-quick@wg0

# Check status
sudo systemctl status wg-quick@wg0

# View logs
journalctl -u wg-quick@wg0 -f
```

## Client Deployment Tips
- Share configs securely
- Replace `$SERVER_IP` in configs
- Generate QR codes:  
  `qrencode -t ansiutf8 < client.conf`

## Important Notes
- **Always run with sudo**
- Default quota: 50GB per non-admin client
- Admin clients bypass bandwidth restrictions
- Config files contain private keys - handle securely!
- All changes persist across reboots

---

## Usage Flow
1. Initialize server once
2. Add clients as needed
3. Delete clients when access should be revoked
4. Monitor usage periodically

---


*For support issues, please open a GitHub ticket or Telegram
https://t.me/level_nine_proxy_support

# Follow me on 
* Telegram    : https://t.me/level_nine_proxy , https://t.me/level_nine_proxy_group
* Facebook    : 
* Instagram   :
* Whatsapp    :
* Youtube     :
* Tic Tok     :
  
