#!/bin/bash

# WireGuard Interface
WG_INTERFACE="wg0"
WG_CONFIG="/etc/wireguard/wg0.conf"
CLIENT_DIR="/etc/wireguard/clients"
SUBNET_FILE="/etc/wireguard/used_subnets"
LOG_FILE="/var/log/wireguard_server.log"

# Install WireGuard
install_wireguard() {
  echo "Installing WireGuard..." | tee -a $LOG_FILE
  sudo apt update && sudo apt install -y wireguard qrencode
}

# Generate Server Keys
generate_server_keys() {
  if [ ! -f "/etc/wireguard/server_private.key" ]; then
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
  fi
}

# Detect Public IP of VPS
detect_public_ip() {
  SERVER_IP=$(curl -s ifconfig.me)
  echo "Detected Public IP: $SERVER_IP" | tee -a $LOG_FILE
}

# Get Next Available Subnet
get_next_subnet() {
  touch "$SUBNET_FILE"
  for i in {1..254}; do
    subnet="10.10.${i}.0/24"
    if ! grep -q "$subnet" "$SUBNET_FILE"; then
      echo "$subnet" >> "$SUBNET_FILE"
      echo "$subnet"
      return
    fi
  done
  echo ""  # No subnets available
}

# Configure WireGuard Server
configure_server() {
  detect_public_ip
  echo "Configuring WireGuard Server..." | tee -a $LOG_FILE
  cat > $WG_CONFIG <<EOL
[Interface]
PrivateKey = $(cat /etc/wireguard/server_private.key)
Address = 10.10.0.1/16
ListenPort = 51820
SaveConfig = true
PostUp = iptables -t nat -A POSTROUTING -o eth0 -s 10.10.0.0/16 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -s 10.10.0.0/16 -j MASQUERADE
EOL
  sudo systemctl enable wg-quick@$WG_INTERFACE
  sudo systemctl start wg-quick@$WG_INTERFACE
}

# Configure Firewall
configure_firewall() {
  echo "Configuring Firewall..." | tee -a $LOG_FILE
  sudo sysctl -w net.ipv4.ip_forward=1
  sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
  sudo ufw allow 51820/udp
}

# Add New Client
add_client() {
  CLIENT_NAME=$1
  if [[ -z "$CLIENT_NAME" ]]; then
    echo "Usage: server-vpn add <client_name>"
    exit 1
  fi

  CLIENT_SUBNET=$(get_next_subnet)
  if [ -z "$CLIENT_SUBNET" ]; then
    echo "No more subnets available!"
    exit 1
  fi

  CLIENT_PRIVATE_KEY=$(wg genkey)
  CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)

  CLIENT_IP=$(echo "$CLIENT_SUBNET" | awk -F. '{print $1"."$2"."$3".1"}')

  echo "[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_SUBNET" >> $WG_CONFIG

  sudo systemctl restart wg-quick@$WG_INTERFACE

  mkdir -p $CLIENT_DIR
  CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}.conf"
  cat > $CLIENT_CONFIG <<EOL
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/24
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOL

  chmod 600 "$CLIENT_CONFIG"
  echo "Client '$CLIENT_NAME' added! Config saved at: $CLIENT_CONFIG"
}

# Remove a Client
remove_client() {
  CLIENT_NAME=$1
  if [[ -z "$CLIENT_NAME" ]]; then
    echo "Usage: server-vpn remove <client_name>"
    exit 1
  fi

  CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}.conf"
  if [ ! -f "$CLIENT_CONFIG" ]; then
    echo "Client '$CLIENT_NAME' not found!"
    exit 1
  fi

  CLIENT_PUBLIC_KEY=$(grep "PrivateKey" "$CLIENT_CONFIG" | cut -d' ' -f3 | wg pubkey)

  sudo sed -i "/$CLIENT_PUBLIC_KEY/,+1d" "$WG_CONFIG"
  sudo rm -f "$CLIENT_CONFIG"

  sudo systemctl restart wg-quick@$WG_INTERFACE
  echo "Client '$CLIENT_NAME' removed!"
}

# List Clients
list_clients() {
  echo "Registered VPN Clients:"
  ls -1 $CLIENT_DIR | sed 's/\.conf$//'
}

# Uninstall WireGuard
uninstall_wireguard() {
  echo "Removing WireGuard..." | tee -a $LOG_FILE
  sudo systemctl stop wg-quick@$WG_INTERFACE
  sudo systemctl disable wg-quick@$WG_INTERFACE
  sudo apt remove --purge -y wireguard qrencode
  sudo rm -rf /etc/wireguard
  echo "WireGuard removed!"
}

# Main Execution
case "$1" in
  install)
    install_wireguard
    generate_server_keys
    configure_server
    configure_firewall
    echo "WireGuard Server Installed!"
    ;;
  add)
    add_client $2
    ;;
  remove)
    remove_client $2
    ;;
  list)
    list_clients
    ;;
  uninstall)
    uninstall_wireguard
    ;;
  *)
    echo "Usage: server-vpn {install|add <client_name>|remove <client_name>|list|uninstall}"
    exit 1
    ;;
esac
