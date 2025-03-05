#!/bin/bash

# WireGuard Server Configuration
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

# Get the Next Available Subnet
get_next_subnet() {
  touch "$SUBNET_FILE"
  local last_octet=1
  local max_octet=254

  while [ $last_octet -le $max_octet ]; do
    local subnet="10.10.${last_octet}.0/24"
    if ! grep -q "$subnet" "$SUBNET_FILE"; then
      echo "$subnet" >> "$SUBNET_FILE"
      echo "$subnet"
      return
    fi
    ((last_octet++))
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
}

# Block communication between clients but allow VPS access
block_inter_client_traffic() {
  iptables -D FORWARD -i $WG_INTERFACE -s 10.10.0.0/16 -d 10.10.0.0/16 -j DROP 2>/dev/null
  iptables -D FORWARD -i $WG_INTERFACE -s 10.10.0.1 -j ACCEPT 2>/dev/null

  iptables -A FORWARD -i $WG_INTERFACE -s 10.10.0.0/16 -d 10.10.0.0/16 -j DROP
  iptables -A FORWARD -i $WG_INTERFACE -s 10.10.0.1 -j ACCEPT  # Allow VPS to access all clients
}

# Enable IP Forwarding and Firewall Rules
configure_firewall() {
  echo "Configuring Firewall..." | tee -a $LOG_FILE
  sudo sysctl -w net.ipv4.ip_forward=1
  sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
  sudo ufw allow 51820/udp

  block_inter_client_traffic
}

# Add a New Client
add_client() {
  CLIENT_NAME=$1
  if [[ -z "$CLIENT_NAME" ]]; then
    echo "Usage: $0 add <client_name>"
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

  systemctl restart wg-quick@$WG_INTERFACE

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
    echo "Usage: $0 remove <client_name>"
    exit 1
  fi

  CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}.conf"
  if [[ ! -f "$CLIENT_CONFIG" ]]; then
    echo "Client configuration not found!"
    exit 1
  fi

  CLIENT_IP=$(grep "Address" "$CLIENT_CONFIG" | awk '{print $3}' | cut -d'/' -f1)
  sed -i "/$CLIENT_IP/d" "$WG_CONFIG"
  rm -f "$CLIENT_CONFIG"

  systemctl restart wg-quick@$WG_INTERFACE
  echo "Client '$CLIENT_NAME' removed!"
}

# List all Clients
list_clients() {
  echo "Registered Clients:"
  ls $CLIENT_DIR/*.conf 2>/dev/null | xargs -n 1 basename | sed 's/.conf//'
}

# Uninstall WireGuard and Remove All Clients
uninstall_wireguard() {
  echo "Uninstalling WireGuard..." | tee -a $LOG_FILE
  systemctl stop wg-quick@$WG_INTERFACE
  apt remove --purge -y wireguard
  rm -rf /etc/wireguard
  echo "WireGuard removed!"
}

# Check if the script was updated and apply necessary changes
update_existing_configs() {
  echo "Checking for existing configurations..." | tee -a $LOG_FILE
  if [[ -f "$WG_CONFIG" ]]; then
    block_inter_client_traffic
    systemctl restart wg-quick@$WG_INTERFACE
  fi
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
  update)
    update_existing_configs
    ;;
  *)
    echo "Usage: $0 {install|add <client_name>|remove <client_name>|list|uninstall|update}"
    exit 1
    ;;
esac
