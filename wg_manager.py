"""
WireGuard VPN Management System with CLI API
Usage: 
- Direct CLI: sudo python3 wg_manager.py <command>
- Remote API: curl -u admin:PASSWORD http://server:5000/api/...
"""
#!/usr/bin/env python3
import os
import subprocess
import argparse
import sys
import json
import socket
import re
from pathlib import Path
from datetime import datetime
from functools import wraps
import hashlib
import secrets
from flask import Flask, request, jsonify, send_file, Response

# Configuration
WG_DIR = "/etc/wireguard"
CONFIG_DIR = Path.home() / "wireguard_clients"
CLIENT_DB = CONFIG_DIR / "clients.json"
BACKUP_DIR = CONFIG_DIR / "backups"
WEB_CONFIG = CONFIG_DIR / "web_config.json"
DNS_SERVER = "1.1.1.1, 8.8.8.8"
VPN_SUBNET = "10.0.0.0/24"
PORT = 51820
DEFAULT_QUOTA = 1000 * 1024 * 1024 * 1024  # 1TB in bytes

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ==================== AUTHENTICATION ====================

def load_web_config():
    """Load web interface configuration"""
    if WEB_CONFIG.exists():
        with open(WEB_CONFIG) as f:
            return json.load(f)
    
    # Default config with admin password
    default_password = secrets.token_urlsafe(12)
    config = {
        "username": "admin",
        "password_hash": hashlib.sha256(default_password.encode()).hexdigest(),
        "default_password": default_password,
        "domain": "",
        "first_login": True
    }
    
    WEB_CONFIG.parent.mkdir(exist_ok=True)
    with open(WEB_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(WEB_CONFIG, 0o600)
    
    return config

def save_web_config(config):
    """Save web interface configuration"""
    with open(WEB_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(WEB_CONFIG, 0o600)

def check_auth(username, password):
    """Check if credentials are valid"""
    config = load_web_config()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return username == config["username"] and password_hash == config["password_hash"]

def requires_auth(f):
    """Decorator for authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({
                'success': False,
                'error': 'Authentication required. Use: curl -u admin:PASSWORD'
            }), 401
        return f(*args, **kwargs)
    return decorated

# ==================== WIREGUARD CORE FUNCTIONS ====================

def check_root():
    """Ensure script is run as root"""
    if os.geteuid() != 0:
        print("❌ Error: This script must be run as root")
        print("   Run with: sudo python3 wireguard_manager.py")
        sys.exit(1)

def get_public_ip():
    """Get server's public IP address"""
    try:
        # Try multiple methods to get public IP
        methods = [
            "curl -s ifconfig.me",
            "curl -s api.ipify.org",
            "curl -s icanhazip.com",
            "dig +short myip.opendns.com @resolver1.opendns.com"
        ]
        
        for method in methods:
            try:
                ip = subprocess.check_output(method, shell=True, timeout=5).decode().strip()
                if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    return ip
            except:
                continue
        
        # Fallback: get from network interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "YOUR_SERVER_IP"

def get_network_interface():
    """Detect default network interface"""
    try:
        result = subprocess.check_output(
            "ip route show default | awk '{print $5}'",
            shell=True
        ).decode().strip()
        return result if result else "eth0"
    except:
        return "eth0"

def load_client_db():
    """Load client database"""
    CONFIG_DIR.mkdir(exist_ok=True, mode=0o700)
    if CLIENT_DB.exists():
        with open(CLIENT_DB) as f:
            return json.load(f)
    return {
        "clients": {},
        "server_public_key": "",
        "server_ip": get_public_ip(),
        "created": datetime.now().isoformat()
    }

def save_client_db(db):
    """Save client database securely"""
    temp_file = CLIENT_DB.with_suffix('.tmp')
    with open(temp_file, "w") as f:
        json.dump(db, f, indent=2)
    temp_file.replace(CLIENT_DB)
    os.chmod(CLIENT_DB, 0o600)

def install_dependencies():
    """Install required packages"""
    print("📦 Installing dependencies...")
    packages = ["wireguard", "wireguard-tools", "iptables", "qrencode"]
    
    # Detect OS
    try:
        with open("/etc/os-release") as f:
            os_info = f.read().lower()
        
        if "ubuntu" in os_info or "debian" in os_info:
            subprocess.run(["apt", "update"], check=True)
            subprocess.run(["apt", "install", "-y"] + packages, check=True)
        elif "centos" in os_info or "rhel" in os_info:
            subprocess.run(["yum", "install", "-y", "epel-release"], check=True)
            subprocess.run(["yum", "install", "-y"] + packages, check=True)
        else:
            print("⚠️  Unknown OS. Please install manually: wireguard qrencode")
    except Exception as e:
        print(f"⚠️  Warning: Could not auto-install packages: {e}")

def enable_ip_forwarding():
    """Enable IP forwarding permanently"""
    print("🔧 Enabling IP forwarding...")
    
    # Enable temporarily
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    
    # Make permanent
    sysctl_conf = Path("/etc/sysctl.conf")
    content = sysctl_conf.read_text() if sysctl_conf.exists() else ""
    
    if "net.ipv4.ip_forward" not in content:
        with open(sysctl_conf, "a") as f:
            f.write("\n# Enable IP forwarding for WireGuard\n")
            f.write("net.ipv4.ip_forward=1\n")
    
    subprocess.run(["sysctl", "-p"], check=True)

def init_server():
    """Initialize WireGuard server"""
    wg_conf = Path(WG_DIR) / "wg0.conf"
    
    if wg_conf.exists():
        print("✅ WireGuard server already initialized")
        return True
    
    print("🚀 Initializing WireGuard server...")
    
    # Install dependencies
    install_dependencies()
    
    # Create WireGuard directory
    Path(WG_DIR).mkdir(exist_ok=True, mode=0o700)
    
    # Generate server keys
    print("🔑 Generating server keys...")
    server_private = subprocess.check_output(
        "wg genkey", shell=True
    ).decode().strip()
    
    server_public = subprocess.check_output(
        f"echo '{server_private}' | wg pubkey", shell=True
    ).decode().strip()
    
    # Save keys
    (Path(WG_DIR) / "privatekey").write_text(server_private)
    os.chmod(Path(WG_DIR) / "privatekey", 0o600)
    (Path(WG_DIR) / "publickey").write_text(server_public)
    
    # Get network interface
    interface = get_network_interface()
    print(f"🌐 Detected network interface: {interface}")
    
    # Enable IP forwarding
    enable_ip_forwarding()
    
    # Create server configuration
    server_ip = VPN_SUBNET.replace("0/24", "1/24")
    server_conf = f"""# WireGuard Server Configuration
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

[Interface]
PrivateKey = {server_private}
Address = {server_ip}
ListenPort = {PORT}
SaveConfig = false

# NAT and forwarding rules
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE

"""
    wg_conf.write_text(server_conf)
    os.chmod(wg_conf, 0o600)
    
    # Configure firewall
    print("🔥 Configuring firewall...")
    try:
        # Try UFW first
        subprocess.run(["ufw", "allow", f"{PORT}/udp"], check=False)
    except:
        try:
            # Try firewalld
            subprocess.run(["firewall-cmd", "--permanent", "--add-port", f"{PORT}/udp"], check=False)
            subprocess.run(["firewall-cmd", "--reload"], check=False)
        except:
            print("⚠️  Please manually allow port", PORT, "UDP in your firewall")
    
    # Enable and start WireGuard
    print("▶️  Starting WireGuard service...")
    subprocess.run(["systemctl", "enable", "wg-quick@wg0"], check=True)
    subprocess.run(["systemctl", "start", "wg-quick@wg0"], check=True)
    
    # Update database
    db = load_client_db()
    db["server_public_key"] = server_public
    db["server_ip"] = get_public_ip()
    db["interface"] = interface
    save_client_db(db)
    
    print(f"✅ WireGuard server initialized successfully!")
    print(f"   Server IP: {db['server_ip']}")
    print(f"   Listening on port: {PORT}")
    return True

def get_next_available_ip():
    """Get next available IP in subnet"""
    db = load_client_db()
    used_ips = set()
    
    for client_data in db["clients"].values():
        ip_last_octet = int(client_data["ip"].split(".")[-1])
        used_ips.add(ip_last_octet)
    
    # Start from .2 (server is .1)
    for i in range(2, 255):
        if i not in used_ips:
            return f"10.0.0.{i}"
    
    return None

def generate_client_keys():
    """Generate client keypair"""
    private = subprocess.check_output("wg genkey", shell=True).decode().strip()
    public = subprocess.check_output(
        f"echo '{private}' | wg pubkey", shell=True
    ).decode().strip()
    return private, public

def add_client(username, is_admin=False, quota_gb=None):
    """Add a new client"""
    db = load_client_db()
    
    # Check if client exists
    if username in db["clients"]:
        return False, f"Client '{username}' already exists"
    
    # Get next IP
    client_ip = get_next_available_ip()
    if not client_ip:
        return False, "No available IP addresses in subnet"
    
    # Generate keys
    client_private, client_public = generate_client_keys()
    server_public = db.get("server_public_key", "")
    server_ip = db.get("server_ip", get_public_ip())
    
    # Calculate quota
    if is_admin:
        quota = "unlimited"
    elif quota_gb:
        quota = quota_gb * 1024 * 1024 * 1024
    else:
        quota = DEFAULT_QUOTA
    
    # Get domain from config
    config = load_web_config()
    domain = config.get('domain', server_ip)
    
    # Create client config
    config_content = f"""[Interface]
# Client: {username}
# Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
PrivateKey = {client_private}
Address = {client_ip}/24
DNS = {DNS_SERVER}

[Peer]
PublicKey = {server_public}
Endpoint = {domain}:{PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    
    # Save client config
    CONFIG_DIR.mkdir(exist_ok=True, mode=0o700)
    config_file = CONFIG_DIR / f"{username}.conf"
    config_file.write_text(config_content)
    os.chmod(config_file, 0o600)
    
    # Add peer to server config
    server_conf = Path(WG_DIR) / "wg0.conf"
    peer_entry = f"""
# Client: {username}
[Peer]
PublicKey = {client_public}
AllowedIPs = {client_ip}/32
"""
    
    with open(server_conf, "a") as f:
        f.write(peer_entry)
    
    # Update database
    db["clients"][username] = {
        "ip": client_ip,
        "public_key": client_public,
        "admin": is_admin,
        "quota": quota,
        "created": datetime.now().isoformat(),
        "bytes_used": 0
    }
    save_client_db(db)
    
    # Apply bandwidth rules if not admin
    if not is_admin:
        apply_bandwidth_limit(client_ip, quota)
    
    # Reload WireGuard
    subprocess.run(
        ["wg", "syncconf", "wg0", str(server_conf)],
        check=True,
        capture_output=True
    )
    
    return True, {
        'username': username,
        'ip': client_ip,
        'admin': is_admin,
        'quota': 'Unlimited' if is_admin else f'{quota / (1024**3):.0f}GB',
        'config': config_content,
        'config_file': str(config_file)
    }

def apply_bandwidth_limit(client_ip, quota_bytes):
    """Apply bandwidth limit using iptables"""
    if quota_bytes == "unlimited":
        return True
    
    # Remove existing rules for this IP
    try:
        rules = subprocess.check_output(
            ["iptables", "-S", "FORWARD"], text=True
        ).splitlines()
        
        for rule in rules:
            if client_ip in rule:
                rule_parts = rule.split()
                if rule_parts[0] == "-A":
                    rule_parts[0] = "-D"
                    subprocess.run(["iptables"] + rule_parts, check=False)
    except:
        pass
    
    # Add quota rule
    subprocess.run([
        "iptables", "-I", "FORWARD", "1",
        "-s", client_ip,
        "-m", "quota", "--quota", str(quota_bytes),
        "-j", "ACCEPT"
    ], check=False)
    
    # Add drop rule after quota exceeded
    subprocess.run([
        "iptables", "-A", "FORWARD",
        "-s", client_ip,
        "-j", "DROP"
    ], check=False)
    
    return True

def generate_qr_code(username):
    """Generate QR code for mobile client"""
    config_file = CONFIG_DIR / f"{username}.conf"
    
    if not config_file.exists():
        return False, "Client not found"
    
    try:
        result = subprocess.run(
            ["qrencode", "-t", "PNG", "-o", "-"],
            input=config_file.read_text().encode(),
            capture_output=True
        )
        
        if result.returncode == 0:
            import base64
            return True, base64.b64encode(result.stdout).decode()
        else:
            return False, "QR generation failed"
    except FileNotFoundError:
        return False, "qrencode not installed"

def get_connected_peers():
    """Get list of connected peers"""
    try:
        output = subprocess.check_output(
            ["wg", "show", "wg0", "dump"],
            text=True
        ).splitlines()
        
        connected = {}
        for line in output[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                connected[parts[0]] = {
                    "endpoint": parts[2] if parts[2] != "(none)" else "N/A",
                    "last_handshake": int(parts[4]),
                    "rx_bytes": int(parts[5]),
                    "tx_bytes": int(parts[6])
                }
        return connected
    except:
        return {}

def delete_client(username):
    """Delete a client"""
    db = load_client_db()
    
    if username not in db["clients"]:
        return False, "Client not found"
    
    client_data = db["clients"][username]
    client_ip = client_data["ip"]
    
    # Remove from server config
    server_conf = Path(WG_DIR) / "wg0.conf"
    lines = server_conf.read_text().splitlines()
    
    new_lines = []
    skip_next = 0
    
    for line in lines:
        if skip_next > 0:
            skip_next -= 1
            continue
        
        if f"# Client: {username}" in line:
            skip_next = 2
            continue
        
        new_lines.append(line)
    
    server_conf.write_text('\n'.join(new_lines))
    
    # Remove iptables rules
    try:
        rules = subprocess.check_output(
            ["iptables", "-S", "FORWARD"], text=True
        ).splitlines()
        
        for rule in rules:
            if client_ip in rule:
                rule_parts = rule.split()
                if rule_parts[0] == "-A":
                    rule_parts[0] = "-D"
                    subprocess.run(["iptables"] + rule_parts, check=False)
    except:
        pass
    
    # Remove config file
    config_file = CONFIG_DIR / f"{username}.conf"
    if config_file.exists():
        config_file.unlink()
    
    # Remove from database
    del db["clients"][username]
    save_client_db(db)
    
    # Reload WireGuard
    subprocess.run(
        ["wg", "syncconf", "wg0", str(server_conf)],
        check=True,
        capture_output=True
    )
    
    return True, f"Client '{username}' deleted"

def get_server_status():
    """Get WireGuard server status"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "wg-quick@wg0"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def backup_configs():
    """Backup all client configurations"""
    BACKUP_DIR.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = BACKUP_DIR / f"wireguard_backup_{timestamp}.tar.gz"
    
    try:
        subprocess.run([
            "tar", "-czf", str(backup_file),
            "-C", str(CONFIG_DIR.parent),
            CONFIG_DIR.name
        ], check=True)
        
        return True, str(backup_file)
    except Exception as e:
        return False, str(e)

def reset_bandwidth(username=None):
    """Reset bandwidth counters"""
    if username:
        # Reset specific client
        db = load_client_db()
        if username not in db["clients"]:
            return False, f"Client '{username}' not found"
        
        client_ip = db["clients"][username]["ip"]
        quota = db["clients"][username]["quota"]
        
        if quota != "unlimited":
            apply_bandwidth_limit(client_ip, quota)
        
        return True, f"Bandwidth reset for {username}"
    else:
        # Reset all non-admin clients
        db = load_client_db()
        for username, data in db["clients"].items():
            if not data["admin"] and data["quota"] != "unlimited":
                apply_bandwidth_limit(data["ip"], data["quota"])
        
        return True, "Bandwidth reset for all clients"

# ==================== CLI FUNCTIONS ====================

def cli_list_clients():
    """CLI: List all clients"""
    db = load_client_db()
    
    if not db["clients"]:
        print("ℹ️  No clients configured yet")
        return
    
    connected_peers = get_connected_peers()
    
    print(f"\n{'Username':<20} {'IP':<15} {'Role':<10} {'Quota':<15} {'Status'}")
    print("=" * 75)
    
    for username, data in sorted(db["clients"].items()):
        role = "Admin" if data["admin"] else "User"
        quota = "Unlimited" if data["quota"] == "unlimited" else f"{data['quota'] / (1024**3):.0f}GB"
        
        # Check connection status
        pub_key = data["public_key"]
        if pub_key in connected_peers:
            last_hs = int(connected_peers[pub_key]["last_handshake"])
            if last_hs < 180:  # Less than 3 minutes ago
                status = "🟢 Connected"
            else:
                status = "🟡 Idle"
        else:
            status = "⚪ Disconnected"
        
        print(f"{username:<20} {data['ip']:<15} {role:<10} {quota:<15} {status}")

def cli_show_client_config(username):
    """CLI: Display client configuration"""
    config_file = CONFIG_DIR / f"{username}.conf"
    
    if not config_file.exists():
        print(f"❌ Error: Client '{username}' not found")
        return False
    
    print(f"\n📄 Configuration for {username}:")
    print("=" * 50)
    print(config_file.read_text())
    print("=" * 50)
    print(f"\nConfig file: {config_file}")
    return True

def cli_generate_qr_code(username):
    """CLI: Generate QR code for mobile client"""
    config_file = CONFIG_DIR / f"{username}.conf"
    
    if not config_file.exists():
        print(f"❌ Error: Client '{username}' not found")
        return False
    
    print(f"\n📱 QR Code for {username}:")
    print("=" * 50)
    
    try:
        subprocess.run(["qrencode", "-t", "ansiutf8", "-r", str(config_file)])
        print("=" * 50)
        print("\nScan this QR code with the WireGuard mobile app")
        return True
    except FileNotFoundError:
        print("❌ qrencode not installed. Install with:")
        print("   apt install qrencode")
        return False

def cli_show_status():
    """CLI: Show server status and statistics"""
    print("\n🖥️  WireGuard Server Status")
    print("=" * 60)
    
    db = load_client_db()
    print(f"Server IP: {db.get('server_ip', 'N/A')}")
    print(f"Port: {PORT}")
    print(f"Total Clients: {len(db['clients'])}")
    
    # Service status
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "wg-quick@wg0"],
            capture_output=True,
            text=True
        )
        status = "🟢 Running" if result.returncode == 0 else "🔴 Stopped"
        print(f"Service Status: {status}")
    except:
        print("Service Status: Unknown")
    
    # Interface statistics
    try:
        wg_output = subprocess.check_output(
            ["wg", "show", "wg0"],
            text=True
        )
        print("\n📊 Interface Statistics:")
        print("-" * 60)
        print(wg_output)
    except:
        print("\n⚠️  Could not retrieve interface statistics")

# ==================== API ROUTES ====================

@app.route('/api/setup', methods=['POST'])
@requires_auth
def api_setup():
    """Initial setup - set domain and change password"""
    try:
        data = request.json
        new_password = data.get('new_password')
        domain = data.get('domain')
        
        config = load_web_config()
        db = load_client_db()
        
        if not domain:
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            })
        
        # Update domain
        config['domain'] = domain
        db['domain'] = domain
        save_web_config(config)
        save_client_db(db)
        
        # Update password if provided
        if new_password:
            config['password_hash'] = hashlib.sha256(new_password.encode()).hexdigest()
            config['first_login'] = False
            config.pop('default_password', None)
            save_web_config(config)
        
        # Ensure server is initialized
        if not (Path(WG_DIR) / "wg0.conf").exists():
            init_server()
        
        return jsonify({
            'success': True,
            'message': 'Setup completed successfully',
            'domain': domain
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/status')
@requires_auth
def api_status():
    """Get server status"""
    try:
        server_running = get_server_status()
        db = load_client_db()
        config = load_web_config()
        connected_peers = get_connected_peers()
        
        connected_count = 0
        for client_data in db['clients'].values():
            if client_data['public_key'] in connected_peers:
                connected_count += 1
        
        return jsonify({
            'success': True,
            'server': {
                'running': server_running,
                'domain': config.get('domain', 'Not set'),
                'public_ip': db.get('server_ip', 'Unknown'),
                'port': PORT,
                'interface': db.get('interface', 'Unknown')
            },
            'clients': {
                'total': len(db['clients']),
                'connected': connected_count
            },
            'first_login': config.get('first_login', False)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clients', methods=['GET'])
@requires_auth
def api_list_clients():
    """List all clients"""
    try:
        db = load_client_db()
        connected_peers = get_connected_peers()
        
        clients = []
        for username, data in db['clients'].items():
            pub_key = data['public_key']
            
            if pub_key in connected_peers:
                last_hs = connected_peers[pub_key]['last_handshake']
                status = "connected" if last_hs < 180 else "idle"
            else:
                status = "disconnected"
            
            clients.append({
                'username': username,
                'ip': data['ip'],
                'admin': data.get('admin', False),
                'status': status,
                'created': data.get('created', 'Unknown')
            })
        
        return jsonify({
            'success': True,
            'clients': clients
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clients/add', methods=['POST'])
@requires_auth
def api_add_client():
    """Add a new client"""
    try:
        data = request.json
        username = data.get('username')
        is_admin = data.get('is_admin', False)
        quota_gb = data.get('quota_gb')
        
        if not username:
            return jsonify({'success': False, 'error': 'Username is required'})
        
        # Ensure server is initialized
        if not (Path(WG_DIR) / "wg0.conf").exists():
            init_server()
        
        success, result = add_client(username, is_admin, quota_gb)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Client {username} added successfully',
                'client': result
            })
        else:
            return jsonify({'success': False, 'error': result})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clients/<username>', methods=['GET'])
@requires_auth
def api_get_client(username):
    """Get client details and config"""
    try:
        config_file = CONFIG_DIR / f"{username}.conf"
        
        if not config_file.exists():
            return jsonify({'success': False, 'error': 'Client not found'})
        
        config_text = config_file.read_text()
        db = load_client_db()
        client_data = db['clients'].get(username, {})
        
        # Get connection status
        connected_peers = get_connected_peers()
        pub_key = client_data.get('public_key', '')
        
        if pub_key in connected_peers:
            status = "connected"
        else:
            status = "disconnected"
        
        return jsonify({
            'success': True,
            'client': {
                'username': username,
                'ip': client_data.get('ip', 'N/A'),
                'admin': client_data.get('admin', False),
                'created': client_data.get('created', 'Unknown'),
                'status': status,
                'config': config_text
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clients/<username>/qr', methods=['GET'])
@requires_auth
def api_get_client_qr(username):
    """Get QR code for client"""
    try:
        success, result = generate_qr_code(username)
        
        if success:
            return jsonify({
                'success': True,
                'qr_code': result,
                'message': 'QR code generated successfully'
            })
        else:
            return jsonify({'success': False, 'error': result})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clients/<username>/download', methods=['GET'])
@requires_auth
def api_download_config(username):
    """Download client config file"""
    try:
        config_file = CONFIG_DIR / f"{username}.conf"
        
        if not config_file.exists():
            return jsonify({'success': False, 'error': 'Client not found'}), 404
        
        return send_file(
            config_file,
            as_attachment=True,
            download_name=f"{username}.conf",
            mimetype='text/plain'
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/clients/<username>', methods=['DELETE'])
@requires_auth
def api_delete_client(username):
    """Delete a client"""
    try:
        success, message = delete_client(username)
        
        if success:
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({'success': False, 'error': message})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/password/change', methods=['POST'])
@requires_auth
def api_change_password():
    """Change admin password"""
    try:
        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'success': False, 'error': 'Missing passwords'})
        
        # Verify current password
        if not check_auth('admin', current_password):
            return jsonify({'success': False, 'error': 'Current password incorrect'})
        
        # Update password
        config = load_web_config()
        config['password_hash'] = hashlib.sha256(new_password.encode()).hexdigest()
        config['first_login'] = False
        config.pop('default_password', None)
        save_web_config(config)
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/server/restart', methods=['POST'])
@requires_auth
def api_restart_server():
    """Restart WireGuard server"""
    try:
        subprocess.run(
            ["systemctl", "restart", "wg-quick@wg0"],
            check=True,
            capture_output=True
        )
        
        return jsonify({
            'success': True,
            'message': 'WireGuard server restarted successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/backup', methods=['GET'])
@requires_auth
def api_backup():
    """Create and download backup"""
    try:
        success, result = backup_configs()
        
        if success:
            return send_file(
                result,
                as_attachment=True,
                download_name=f"wireguard_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz",
                mimetype='application/gzip'
            )
        else:
            return jsonify({'success': False, 'error': result})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bandwidth/reset', methods=['POST'])
@requires_auth
def api_reset_bandwidth():
    """Reset bandwidth counters"""
    try:
        data = request.json
        username = data.get('username') if data else None
        
        success, message = reset_bandwidth(username)
        
        if success:
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({'success': False, 'error': message})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/help', methods=['GET'])
def api_help():
    """Show available API endpoints"""
    help_text = """
WireGuard CLI Management API
============================

Authentication required for all endpoints (except /api/help)
Use: curl -u admin:PASSWORD http://server:5000/ENDPOINT

Endpoints:
----------
GET  /api/status              - Get server status
GET  /api/clients             - List all clients
POST /api/clients/add         - Add a new client
GET  /api/clients/<username>  - Get client details
GET  /api/clients/<username>/qr - Get QR code
GET  /api/clients/<username>/download - Download config
DELETE /api/clients/<username> - Delete a client
POST /api/setup              - Initial setup (set domain, password)
POST /api/password/change    - Change admin password
POST /api/server/restart     - Restart WireGuard server
GET  /api/backup             - Download backup
POST /api/bandwidth/reset   - Reset bandwidth counters

Examples:
---------
1. Check status:
   curl -u admin:password http://server:5000/api/status

2. List clients:
   curl -u admin:password http://server:5000/api/clients

3. Add client:
   curl -u admin:password -X POST -H "Content-Type: application/json" \\
        -d '{"username":"myclient"}' \\
        http://server:5000/api/clients/add

4. Add admin client:
   curl -u admin:password -X POST -H "Content-Type: application/json" \\
        -d '{"username":"adminclient", "is_admin":true}' \\
        http://server:5000/api/clients/add

5. Setup domain and password:
   curl -u admin:password -X POST -H "Content-Type: application/json" \\
        -d '{"domain":"vpn.example.com", "new_password":"newpass"}' \\
        http://server:5000/api/setup
"""
    return Response(help_text, mimetype='text/plain')

# ==================== CLI MAIN ====================

def cli_main():
    """CLI interface main function"""
    parser = argparse.ArgumentParser(
        description="WireGuard VPN Management System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize server
  sudo ./wireguard_manager.py init
  
  # Add regular user with 100GB quota
  sudo ./wireguard_manager.py add myphone --quota 100
  
  # Add admin user (unlimited)
  sudo ./wireguard_manager.py add laptop --admin
  
  # Generate QR code for mobile
  sudo ./wireguard_manager.py qr myphone
  
  # List all clients
  sudo ./wireguard_manager.py list
  
  # Show server status
  sudo ./wireguard_manager.py status
  
  # Delete client
  sudo ./wireguard_manager.py delete oldclient
  
  # Backup configurations
  sudo ./wireguard_manager.py backup
  
  # Reset bandwidth
  sudo ./wireguard_manager.py reset [--username CLIENT]
        """
    )
    
    subparsers = parser.add_subparsers(dest="action", help="Action to perform")
    
    # Init command
    subparsers.add_parser("init", help="Initialize WireGuard server")
    
    # Add command
    add_parser = subparsers.add_parser("add", help="Add new client")
    add_parser.add_argument("username", help="Client username")
    add_parser.add_argument("--admin", action="store_true", help="Create admin user (unlimited bandwidth)")
    add_parser.add_argument("--quota", type=int, help="Bandwidth quota in GB (default: 1000)")
    
    # List command
    subparsers.add_parser("list", help="List all clients")
    
    # Delete command
    del_parser = subparsers.add_parser("delete", help="Delete client")
    del_parser.add_argument("username", help="Client username to delete")
    
    # QR command
    qr_parser = subparsers.add_parser("qr", help="Generate QR code for mobile")
    qr_parser.add_argument("username", help="Client username")
    
    # Show command
    show_parser = subparsers.add_parser("show", help="Show client configuration")
    show_parser.add_argument("username", help="Client username")
    
    # Status command
    subparsers.add_parser("status", help="Show server status")
    
    # Backup command
    subparsers.add_parser("backup", help="Backup all configurations")
    
    # Reset bandwidth
    reset_parser = subparsers.add_parser("reset", help="Reset bandwidth counters")
    reset_parser.add_argument("--username", help="Specific client (default: all)")
    
    # API server command
    api_parser = subparsers.add_parser("api", help="Start API server")
    api_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    api_parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    api_parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    if not args.action:
        parser.print_help()
        sys.exit(1)
    
    # For CLI commands, check root
    if args.action != "api":
        check_root()
    
    # Execute action
    if args.action == "init":
        init_server()
    
    elif args.action == "add":
        if not (Path(WG_DIR) / "wg0.conf").exists():
            init_server()
        success, result = add_client(args.username, args.admin, args.quota)
        if success:
            print(f"✅ {result['username']} created successfully")
            print(f"   IP: {result['ip']}")
            print(f"   Quota: {result['quota']}")
            print(f"   Config: {result['config_file']}")
        else:
            print(f"❌ Error: {result}")
    
    elif args.action == "list":
        cli_list_clients()
    
    elif args.action == "delete":
        success, message = delete_client(args.username)
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ Error: {message}")
    
    elif args.action == "qr":
        cli_generate_qr_code(args.username)
    
    elif args.action == "show":
        cli_show_client_config(args.username)
    
    elif args.action == "status":
        cli_show_status()
    
    elif args.action == "backup":
        success, result = backup_configs()
        if success:
            print(f"✅ Backup created: {result}")
        else:
            print(f"❌ Backup failed: {result}")
    
    elif args.action == "reset":
        success, message = reset_bandwidth(args.username if hasattr(args, 'username') else None)
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ Error: {message}")
    
    elif args.action == "api":
        # Load config and show credentials if first run
        config = load_web_config()
        
        if config.get('first_login', False):
            print("\n" + "="*60)
            print("🔐 FIRST TIME SETUP")
            print("="*60)
            print(f"URL: http://your-server-ip:{args.port}")
            print(f"Default username: admin")
            print(f"Default password: {config['default_password']}")
            print("\nRequired first step:")
            print(f"curl -u admin:{config['default_password']} \\")
            print(f'  -X POST -H "Content-Type: application/json" \\')
            print(f'  -d \'{{"domain":"your-domain.com", "new_password":"your-new-password"}}\' \\')
            print(f'  http://your-server-ip:{args.port}/api/setup')
            print("="*60 + "\n")
        
        print(f"✅ WireGuard API starting on http://{args.host}:{args.port}")
        print(f"📚 API Documentation: curl http://{args.host}:{args.port}/api/help")
        print("   Press Ctrl+C to stop\n")
        
        # Ensure server is initialized
        if not (Path(WG_DIR) / "wg0.conf").exists():
            print("⚠️  WireGuard server not initialized. Auto-initializing...")
            init_server()
        
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)

if __name__ == "__main__":
    cli_main()

