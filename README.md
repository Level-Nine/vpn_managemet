# **Complete WireGuard Manager Usage Guide**

## **Quick Start Commands:**

```bash
# 1. First, navigate to your project directory
cd ~/vpn_managemet/vpn_managemet

# 2. Initialize the WireGuard server (one-time setup)
sudo venv/bin/python wg_manager.py init

# 3. Start the API server for remote management
sudo venv/bin/python wg_manager.py api --port 5000
```

## **📋 Table of Contents**
1. [Local CLI Commands](#local-cli-commands)
2. [Remote API Usage](#remote-api-usage)  
3. [Step-by-Step Setup](#step-by-step-setup-guide)
4. [Client Setup Guides](#client-setup-guides)
5. [Troubleshooting](#troubleshooting)
6. [Advanced Features](#advanced-features)

---

## **Local CLI Commands** (Run on your server)

### **🔧 Server Management**
```bash
# Initialize WireGuard server (one-time)
sudo venv/bin/python wg_manager.py init

# Check server status
sudo venv/bin/python wg_manager.py status

# Restart WireGuard service
sudo systemctl restart wg-quick@wg0
```

### **👥 Client Management**
```bash
# Add a regular user with 50GB quota
sudo venv/bin/python wg_manager.py add myphone --quota 50

# Add admin user (unlimited bandwidth)
sudo venv/bin/python wg_manager.py add laptop --admin

# List all clients
sudo venv/bin/python wg_manager.py list

# Show client configuration
sudo venv/bin/python wg_manager.py show myphone

# Generate QR code for mobile
sudo venv/bin/python wg_manager.py qr myphone

# Delete a client
sudo venv/bin/python wg_manager.py delete myphone
```

### **💾 Backup & Maintenance**
```bash
# Backup all configurations
sudo venv/bin/python wg_manager.py backup

# Reset bandwidth counters for all clients
sudo venv/bin/python wg_manager.py reset

# Reset bandwidth for specific client
sudo venv/bin/python wg_manager.py reset --username myphone
```

---

## **Remote API Usage** (Manage from anywhere)

### **Start the API Server:**
```bash
# On your server, start the API (default port 5000)
sudo venv/bin/python wg_manager.py api

# Or specify custom port
sudo venv/bin/python wg_manager.py api --port 8080 --host 0.0.0.0
```

### **API Examples (using curl):**

```bash
# Get API help
curl http://YOUR_SERVER_IP:5000/api/help

# Check server status
curl -u admin:PASSWORD http://YOUR_SERVER_IP:5000/api/status

# List all clients
curl -u admin:PASSWORD http://YOUR_SERVER_IP:5000/api/clients

# Add new client
curl -u admin:PASSWORD -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"newclient"}' \
  http://YOUR_SERVER_IP:5000/api/clients/add

# Add admin client
curl -u admin:PASSWORD -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"adminpc", "is_admin":true}' \
  http://YOUR_SERVER_IP:5000/api/clients/add

# Get client config
curl -u admin:PASSWORD \
  http://YOUR_SERVER_IP:5000/api/clients/newclient

# Get QR code (for mobile)
curl -u admin:PASSWORD \
  http://YOUR_SERVER_IP:5000/api/clients/newclient/qr

# Download config file
curl -u admin:PASSWORD -o newclient.conf \
  http://YOUR_SERVER_IP:5000/api/clients/newclient/download

# Delete client
curl -u admin:PASSWORD -X DELETE \
  http://YOUR_SERVER_IP:5000/api/clients/newclient
```

---

## **Step-by-Step Setup Guide**

### **Phase 1: Initial Server Setup**

```bash
# 1. SSH into your server
ssh root@your-server-ip

# 2. Clone/download the manager (if not already)
cd ~
git clone https://github.com/your-repo/vpn_managemet.git
cd vpn_managemet

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install dependencies
pip install Flask qrcode[pil] python-dateutil

# 5. Initialize WireGuard server
sudo venv/bin/python wg_manager.py init

# 6. Start API server
sudo venv/bin/python wg_manager.py api --port 5000
```

### **Phase 2: First-Time Configuration**

From another computer, configure your domain and password:

```bash
# Get the default password (shown when API starts)
# Then run:
curl -u admin:DEFAULT_PASSWORD -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "domain":"vpn.yourdomain.com",
    "new_password":"YourSecurePassword123"
  }' \
  http://YOUR_SERVER_IP:5000/api/setup
```

**Important:** Replace `vpn.yourdomain.com` with your actual domain that points to your server IP.

### **Phase 3: Create Your First Client**

```bash
# Create a client for your phone
curl -u admin:YourSecurePassword123 -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"myiphone", "quota_gb":100}' \
  http://YOUR_SERVER_IP:5000/api/clients/add

# Download the config
curl -u admin:YourSecurePassword123 -o myiphone.conf \
  http://YOUR_SERVER_IP:5000/api/clients/myiphone/download
```

---

## **Client Setup Guides**

### **📱 iOS (iPhone/iPad)**
1. Install "WireGuard" from App Store
2. Open app → Tap "+" → "Create from file or archive"
3. Import the downloaded `.conf` file
4. Tap "Add" → Toggle switch to connect

### **🤖 Android**
1. Install "WireGuard" from Play Store
2. Tap "+" → "Create from file or archive"
3. Select the downloaded `.conf` file
4. Tap "Add" → Toggle switch to connect

### **🖥️ Windows**
1. Download WireGuard from https://www.wireguard.com/install/
2. Install and open WireGuard
3. Click "Import tunnel(s) from file"
4. Select your `.conf` file
5. Click "Activate"

### **🍎 macOS**
1. Install from Mac App Store or https://www.wireguard.com/install/
2. Open WireGuard
3. Click "Import tunnel(s) from file"
4. Select your `.conf` file
5. Click "Activate"

### **🐧 Linux**
```bash
# Install WireGuard
sudo apt install wireguard  # Ubuntu/Debian

# Copy config
sudo cp myiphone.conf /etc/wireguard/wg0-client.conf

# Start client
sudo wg-quick up wg0-client

# Check status
sudo wg show

# Stop client
sudo wg-quick down wg0-client
```

---

## **Automated Setup Script**

Save this as `setup.sh` and run `chmod +x setup.sh`:

```bash
#!/bin/bash
# setup.sh - Complete WireGuard Manager Setup

echo "🔧 WireGuard Manager Setup"
echo "=========================="

# Get server IP
SERVER_IP=$(curl -s ifconfig.me)
echo "Detected server IP: $SERVER_IP"

# Ask for domain
read -p "Enter your domain (e.g., vpn.example.com): " DOMAIN
read -p "Enter admin password: " -s PASSWORD
echo

# Step 1: Initialize server
echo "1. Initializing WireGuard server..."
sudo venv/bin/python wg_manager.py init

# Step 2: Start API temporarily
echo "2. Starting API server..."
sudo venv/bin/python wg_manager.py api --port 5001 &
API_PID=$!
sleep 3

# Step 3: Setup domain and password
echo "3. Configuring domain and password..."
curl -u admin:DEFAULT_PASSWORD -X POST \
  -H "Content-Type: application/json" \
  -d "{\"domain\":\"$DOMAIN\", \"new_password\":\"$PASSWORD\"}" \
  http://localhost:5001/api/setup

# Step 4: Stop temporary API
kill $API_PID

# Step 5: Create systemd service
echo "4. Creating system service..."
cat > /etc/systemd/system/wireguard-api.service << EOF
[Unit]
Description=WireGuard Management API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$(pwd)/venv/bin/python wg_manager.py api --host 0.0.0.0 --port 5000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Step 6: Enable and start
systemctl daemon-reload
systemctl enable wireguard-api
systemctl start wireguard-api

echo "✅ Setup complete!"
echo ""
echo "📡 API URL: http://$SERVER_IP:5000"
echo "🔑 Username: admin"
echo "🔐 Password: $PASSWORD"
echo ""
echo "To create your first client:"
echo "curl -u admin:$PASSWORD -X POST \\"
echo '  -H "Content-Type: application/json" \'
echo '  -d \'{"username":"mydevice"}\' \'
echo "  http://$SERVER_IP:5000/api/clients/add"
```

---

## **Daily Operations**

### **Monitoring**
```bash
# Check connected clients
sudo wg show

# Check server status
sudo venv/bin/python wg_manager.py status

# View system logs
journalctl -u wg-quick@wg0 -f
journalctl -u wireguard-api -f
```

### **Adding New Users**
```bash
# Add user with 50GB quota
curl -u admin:password -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"friend", "quota_gb":50}' \
  http://server:5000/api/clients/add

# Send them their config
curl -u admin:password \
  http://server:5000/api/clients/friend/download \
  | mail -s "Your VPN Config" friend@email.com
```

### **Managing Bandwidth**
```bash
# Check bandwidth usage
sudo iptables -L FORWARD -v -n

# Reset user's bandwidth
curl -u admin:password -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"friend"}' \
  http://server:5000/api/bandwidth/reset

# Change user's quota
# Delete and recreate with new quota
curl -u admin:password -X DELETE \
  http://server:5000/api/clients/friend
  
curl -u admin:password -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"friend", "quota_gb":100}' \
  http://server:5000/api/clients/add
```

---

## **Troubleshooting**

### **Common Issues & Solutions:**

#### **1. WireGuard not starting:**
```bash
# Check if module is loaded
lsmod | grep wireguard

# Load module
modprobe wireguard

# Check systemd status
systemctl status wg-quick@wg0
journalctl -u wg-quick@wg0
```

#### **2. Can't connect to API:**
```bash
# Check if API is running
netstat -tulpn | grep :5000

# Check firewall
ufw status
iptables -L

# Allow port 5000
ufw allow 5000/tcp
```

#### **3. Clients can't connect:**
```bash
# Check port is open
nc -zv YOUR_SERVER_IP 51820

# Check DNS resolution
nslookup vpn.yourdomain.com

# Test connectivity
ping vpn.yourdomain.com
```

#### **4. Bandwidth quota not working:**
```bash
# Check iptables rules
iptables -L FORWARD -v -n

# Reset all rules
sudo venv/bin/python wg_manager.py reset
```

### **Debug Mode:**
```bash
# Start API with debug
sudo venv/bin/python wg_manager.py api --debug

# Run CLI with verbose output
sudo venv/bin/python wg_manager.py status --verbose
```

---

## **Advanced Features**

### **1. Auto-renewal Script**
```bash
#!/bin/bash
# auto_renew.sh - Reset bandwidth on 1st of month

# Reset all bandwidth
curl -u admin:password -X POST \
  http://localhost:5000/api/bandwidth/reset

# Email notification
echo "Bandwidth reset for all users" | mail -s "VPN Bandwidth Reset" admin@email.com
```

Add to crontab: `0 0 1 * * /path/to/auto_renew.sh`

### **2. Bulk User Import**
Create `users.txt`:
```
alice 50
bob 100
charlie admin
```

```bash
#!/bin/bash
# import_users.sh

while read USER QUOTA; do
  if [ "$QUOTA" = "admin" ]; then
    curl -u admin:password -X POST \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"$USER\", \"is_admin\":true}" \
      http://localhost:5000/api/clients/add
  else
    curl -u admin:password -X POST \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"$USER\", \"quota_gb\":$QUOTA}" \
      http://localhost:5000/api/clients/add
  fi
done < users.txt
```

### **3. Integration with Monitoring**
```bash
# Export client list to CSV
curl -u admin:password http://localhost:5000/api/clients \
  | jq -r '.clients[] | [.username, .ip, .admin, .status] | @csv' \
  > clients.csv
```

---

## **Quick Reference Card**

### **Server Commands:**
```bash
init         # Initialize WireGuard
status       # Check server status
list         # List all clients
add USER     # Add new client
delete USER  # Remove client
qr USER      # Show QR code
backup       # Backup all configs
reset        # Reset bandwidth
api          # Start management API
```

### **API Endpoints:**
```
GET    /api/status                    # Server status
GET    /api/clients                   # List clients
POST   /api/clients/add              # Add client
GET    /api/clients/:user            # Get client
DELETE /api/clients/:user            # Delete client
GET    /api/clients/:user/qr         # QR code
GET    /api/clients/:user/download   # Config file
POST   /api/setup                    # Initial setup
POST   /api/bandwidth/reset          # Reset quotas
```

### **Ports Used:**
- `51820/UDP` - WireGuard VPN traffic
- `5000/TCP`  - Management API (change with `--port`)

---

## **Getting Help**

```bash
# Show all commands
sudo venv/bin/python wg_manager.py --help

# Get API documentation
curl http://localhost:5000/api/help

# Check logs
tail -f /var/log/syslog | grep wireguard
journalctl -u wireguard-api -f
```

## **Security Notes:**
1. ✅ Always use strong passwords
2. ✅ Change default password immediately
3. ✅ Use HTTPS in production (add nginx + Let's Encrypt)
4. ✅ Regularly backup configurations
5. ✅ Monitor `/var/log/auth.log` for unauthorized access attempts

---

**Need more help?** Check:
- WireGuard official docs: https://www.wireguard.com/
- Flask documentation: https://flask.palletsprojects.com/
- Ubuntu/Debian networking: https://help.ubuntu.com/community/NetworkConfiguration
