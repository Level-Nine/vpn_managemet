#!/usr/bin/env python3
import os
import subprocess
import argparse
import sys
import json
from pathlib import Path

# Configuration
WG_DIR = "/etc/wireguard"
CONFIG_DIR = Path.home() / "wireguard_clients"
CLIENT_DB = CONFIG_DIR / "clients.json"
DNS_SERVER = "1.1.1.1"
VPN_SUBNET = "10.0.0.0/24"
PORT = 51820
DEFAULT_QUOTA = 1000 * 1024 * 1024 * 1024  # 1TB in bytes

def check_root():
    if os.geteuid() != 0:
        print("Error: This script must be run as root", file=sys.stderr)
        sys.exit(1)

def load_client_db():
    if CLIENT_DB.exists():
        with open(CLIENT_DB) as f:
            return json.load(f)
    return {"clients": {}}

def save_client_db(db):
    with open(CLIENT_DB, "w") as f:
        json.dump(db, f, indent=2)

def init_server():
    """Initialize WireGuard server if not already set up"""
    if not (Path(WG_DIR) / "wg0.conf").exists():
        print("Initializing WireGuard server...")
        subprocess.run(["apt", "install", "-y", "wireguard", "iptables-persistent"], check=True)
        subprocess.run(f"umask 077; wg genkey | tee {WG_DIR}/privatekey | wg pubkey > {WG_DIR}/publickey", 
                      shell=True, check=True)
        
        server_conf = f"""[Interface]
PrivateKey = {(Path(WG_DIR) / 'privatekey').read_text().strip()}
Address = {VPN_SUBNET.replace('0/24', '1/24')}
ListenPort = {PORT}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
"""
        (Path(WG_DIR) / "wg0.conf").write_text(server_conf)
        subprocess.run(["systemctl", "enable", "--now", "wg-quick@wg0"], check=True)

def apply_bandwidth_rules(client_ip, is_admin):
    """Configure iptables rules for bandwidth limiting"""
    # Clear existing rules for this IP
    subprocess.run(f"iptables-save | grep -v '--source {client_ip}' | iptables-restore", shell=True)
    
    if is_admin:
        subprocess.run(f"iptables -A FORWARD -s {client_ip} -j ACCEPT", shell=True)
    else:
        subprocess.run(
            f"iptables -A FORWARD -s {client_ip} "
            f"-m quota --quota {DEFAULT_QUOTA} -j ACCEPT",
            shell=True
        )
        subprocess.run(f"iptables -A FORWARD -s {client_ip} -j DROP", shell=True)
    
    subprocess.run("iptables-save > /etc/iptables/rules.v4", shell=True)

def generate_client_config(username, ip_index, is_admin=False):
    """Generate client configuration with bandwidth rules"""
    client_private = subprocess.check_output("wg genkey", shell=True).decode().strip()
    client_public = subprocess.check_output(f"echo '{client_private}' | wg pubkey", shell=True).decode().strip()
    server_public = (Path(WG_DIR) / "publickey").read_text().strip()
    
    client_ip = f"10.0.0.{ip_index}"
    config = f"""[Interface]
PrivateKey = {client_private}
Address = {client_ip}/24
DNS = {DNS_SERVER}

[Peer]
PublicKey = {server_public}
Endpoint = $SERVER_IP:{PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    
    config_file = CONFIG_DIR / f"{username}.conf"
    config_file.write_text(config)
    
    server_conf = Path(WG_DIR) / "wg0.conf"
    peer_entry = f"\n[Peer]\nPublicKey = {client_public}\nAllowedIPs = {client_ip}/32\n"
    server_conf.write_text(server_conf.read_text() + peer_entry)
    
    db = load_client_db()
    db["clients"][username] = {
        "ip": client_ip,
        "public_key": client_public,
        "admin": is_admin,
        "quota": "unlimited" if is_admin else DEFAULT_QUOTA,
        "used": 0
    }
    save_client_db(db)
    
    apply_bandwidth_rules(client_ip, is_admin)
    
    return config_file

def delete_client(username):
    """Remove client configuration"""
    db = load_client_db()
    
    if username not in db["clients"]:
        print(f"Error: Client {username} not found", file=sys.stderr)
        return False
    
    client_data = db["clients"][username]
    
    # Remove from server config
    server_conf = Path(WG_DIR) / "wg0.conf"
    current_conf = server_conf.read_text()
    
    # Find and remove the peer block
    peer_blocks = current_conf.split("[Peer]")
    new_conf = peer_blocks[0]
    
    for block in peer_blocks[1:]:
        if f"AllowedIPs = {client_data['ip']}" not in block:
            new_conf += f"[Peer]{block}"
    
    server_conf.write_text(new_conf)
    
    # Remove iptables rules
    subprocess.run(f"iptables-save | grep -v '--source {client_data['ip']}' | iptables-restore", shell=True)
    subprocess.run("iptables-save > /etc/iptables/rules.v4", shell=True)
    
    # Remove config file
    config_file = CONFIG_DIR / f"{username}.conf"
    if config_file.exists():
        config_file.unlink()
    
    # Remove from database
    del db["clients"][username]
    save_client_db(db)
    
    # Reload WireGuard
    subprocess.run(["wg", "syncconf", "wg0", (Path(WG_DIR) / "wg0.conf").as_posix()], check=True)
    
    print(f"Client {username} deleted successfully")
    return True

def add_clients(num_clients, prefix="client", admin=False):
    """Bulk add clients with bandwidth rules"""
    CONFIG_DIR.mkdir(exist_ok=True)
    existing_ips = get_existing_ips()
    
    try:
        next_ip = max(existing_ips) + 1 if existing_ips else 2
    except ValueError:
        next_ip = 2

    for i in range(num_clients):
        username = f"{prefix}{next_ip - 1:03d}"
        if (CONFIG_DIR / f"{username}.conf").exists():
            print(f"Skipping existing client {username}")
            next_ip += 1
            continue
            
        print(f"Creating {'admin ' if admin else ''}client {username} ({'unlimited' if admin else '100GB'} bandwidth)")
        generate_client_config(username, next_ip, admin)
        next_ip += 1
        
    subprocess.run(["wg", "syncconf", "wg0", (Path(WG_DIR) / "wg0.conf").as_posix()], check=True)

def get_existing_ips():
    """Get list of already assigned IPs"""
    ips = []
    for peer in Path(WG_DIR / "wg0.conf").read_text().split("[Peer]"):
        if "AllowedIPs" in peer:
            ip = peer.split("AllowedIPs = ")[1].split("/")[0]
            ips.append(int(ip.split(".")[-1]))
    return ips

def show_bandwidth_usage():
    """Display current bandwidth usage"""
    db = load_client_db()
    print("\n{:<20} {:<15} {:<10} {:<15}".format(
        "Client", "IP", "Admin", "Bandwidth Used"))
    print("-" * 60)
    
    for client, data in db["clients"].items():
        used = f"{data['used'] / (1024**3):.2f}GB" if data['used'] else "0.00GB"
        admin = "Yes" if data['admin'] else "No"
        print(f"{client:<20} {data['ip']:<15} {admin:<10} {used:<15}")

def main():
    parser = argparse.ArgumentParser(description="WireGuard Client Manager ")
    parser.add_argument("action", choices=["add", "list", "usage", "delete"], help="Action to perform")
    parser.add_argument("-n", "--num-clients", type=int, help="Number of clients to add")
    parser.add_argument("-p", "--prefix", default="client", help="Username prefix")
    parser.add_argument("--admin", action="store_true", help="Create admin clients (unlimited bandwidth)")
    parser.add_argument("--show-configs", action="store_true", help="Display generated config paths")
    parser.add_argument("--username", help="Username for delete operation")
    
    args = parser.parse_args()
    check_root()
    init_server()
    
    if args.action == "add":
        if not args.num_clients:
            print("Error: Specify number of clients with -n", file=sys.stderr)
            sys.exit(1)
            
        add_clients(args.num_clients, args.prefix, args.admin)
        
    elif args.action == "list":
        clients = list(CONFIG_DIR.glob("*.conf"))
        print(f"\n{'Client Name':<20} {'IP Address':<15} {'Admin'}")
        print("-" * 45)
        db = load_client_db()
        for client in clients:
            ip = client.read_text().split("Address = ")[1].split("/")[0]
            admin = "Yes" if db["clients"][client.stem]["admin"] else "No"
            print(f"{client.stem:<20} {ip:<15} {admin}")
    
    elif args.action == "usage":
        show_bandwidth_usage()
    
    elif args.action == "delete":
        if not args.username:
            print("Error: Specify username with --username", file=sys.stderr)
            sys.exit(1)
        delete_client(args.username)
    
    if args.show_configs:
        print(f"\nClient configurations stored in: {CONFIG_DIR}")

if __name__ == "__main__":
    main()
