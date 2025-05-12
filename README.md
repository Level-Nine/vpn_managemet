# INSTALLATION
sudo apt update && sudo apt install -y wireguard iptables-persistent python3
chmod +x wg-manager.py

# SERVER SETUP (run once)
sudo ./wg-manager.py add -n 0

# CLIENT MANAGEMENT
# Add 100 regular clients
sudo ./wg-manager.py add -n 100

# Add 5 admin clients
sudo ./wg-manager.py add -n 5 -p admin --admin

# Add single client
sudo ./wg-manager.py add -n 1 -p user123

# Delete client
sudo ./wg-manager.py delete --username client001

# List all clients
sudo ./wg-manager.py list

# Show bandwidth usage
sudo ./wg-manager.py usage

# CONFIGURATION FILES
# View client configs
sudo ls ~/wireguard_clients

# Download config (from local machine)
scp root@your-server:~/wireguard_clients/client001.conf .

# BANDWIDTH CONTROL
# Reset quota for client (run monthly)
sudo iptables -D FORWARD -s 10.0.0.2 -j DROP
sudo iptables -A FORWARD -s 10.0.0.2 -m quota --quota 107374182400 -j ACCEPT
sudo iptables -A FORWARD -s 10.0.0.2 -j DROP
sudo netfilter-persistent save

# MONITORING
# Live traffic monitoring
sudo watch -n 1 "wg show"

# Bandwidth test (server)
iperf3 -s

# Bandwidth test (client)
iperf3 -c SERVER_IP -P 10


USAGE FLOW :

1 INITIALIZE SERVER ONCE 
2 ADD CLIENTS AS NEEDED
3 DELETE CLIENTS WHEN ACCESS SHOULD BE REVOKED
4 MONITOR USAGE PERIODICALLY


THE SCRIPT PROVIDES COMPLETE LIFECYCLE MANAGEMENT FOR WIREGUARD CLIENTS WITH 
BANDWITH CONTROLS.ALL CHANGES ARE PERSISTENT ACROSS REBOOTS.
