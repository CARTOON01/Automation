#!/bin/bash
# Include comments on every update for documentation purposes


# Lock file to prevent multiple instances
LOCK_FILE="/tmp/wireguard_setup.lock"

# Check if script is already running to avoid multiple instances
if [ -e "$LOCK_FILE" ]; then
  echo "Script is already running! Exiting..."
  exit 1
fi

# Create lock file
touch $LOCK_FILE
cleanup() { rm -f "$LOCK_FILE"; }
trap cleanup EXIT

# Define variables
WG_INTERFACE="wg0"
WG_CONFIG="/etc/wireguard/wg0.conf"
CLIENT_DIR="/etc/wireguard/clients"
LOG_FILE="/var/log/wireguard_client.log"
IP_RANGE_START="10.10.1.100"  # Start of the IP address range
IP_RANGE_END="10.10.1.200"    # End of the IP address range
ASSIGNED_IPS_FILE="/etc/wireguard/assigned_ips.txt"

# Ensure log file exists
touch $LOG_FILE && chmod 600 $LOG_FILE
touch $ASSIGNED_IPS_FILE && chmod 600 $ASSIGNED_IPS_FILE

# Install WireGuard
install_wireguard() {
  echo "Installing WireGuard..."
  sudo apt update
  sudo apt install -y wireguard qrencode
}

# Generate Server Keys
generate_server_keys() {
  if [ ! -f "/etc/wireguard/server_private.key" ]; then
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
  fi
}

# Detect Public IP for the VPS
detect_public_ip() {
  SERVER_IP=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
  echo "Detected Public IP: $SERVER_IP"
}

# Configure WireGuard Server
configure_server() {
  detect_public_ip
  echo "Enabling IP forwarding..."
  sudo sysctl -w net.ipv4.ip_forward=1
  sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
  cat > $WG_CONFIG <<EOL
[Interface]
PrivateKey = $(cat /etc/wireguard/server_private.key)
Address = 10.10.0.1/16
ListenPort = 51820
SaveConfig = true
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -j MASQUERADE
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -j MASQUERADE
EOL
}

# Enable Firewall & Start WireGuard
configure_firewall() {
  sudo ufw allow 51820/udp
  sudo systemctl enable wg-quick@$WG_INTERFACE
  sudo systemctl start wg-quick@$WG_INTERFACE
}

# Function to check if an IP is within the range
is_ip_in_range() {
  local ip=$1
  local start_ip=$(echo "$IP_RANGE_START" | awk -F. '{print $1 * 256**3 + $2 * 256**2 + $3 * 256 + $4}')
  local end_ip=$(echo "$IP_RANGE_END" | awk -F. '{print $1 * 256**3 + $2 * 256**2 + $3 * 256 + $4}')
  local check_ip=$(echo "$ip" | awk -F. '{print $1 * 256**3 + $2 * 256**2 + $3 * 256 + $4}')

  if (( check_ip >= start_ip && check_ip <= end_ip )); then
    return 0  # IP is in range
  else
    return 1  # IP is not in range
  fi
}

# Function to find a free IP address
find_free_ip() {
  local ip_start=$(echo "$IP_RANGE_START" | awk -F. '{print $1"."$2".0."$4}')
  local ip_end=$(echo "$IP_RANGE_END" | awk -F. '{print $1"."$2".0."$4}')
  local ip=$ip_start

  while is_ip_in_range "$ip"; do
    if grep -q "^$ip$" "$ASSIGNED_IPS_FILE"; then
      # IP is assigned, increment to the next IP
      IFS='.' read -r a b c d <<< "$ip"
      ((d++))
      if (( d > 254 )); then
        echo "No available IP addresses in the range!"
        return 1
      fi
      ip="$a.$b.$c.$d"
    else
      # IP is not assigned, check if it's in range and return it
      echo "$ip"
      return 0
    fi
  done
  echo "No available IP addresses in the range!"
  return 1
}

# Function to assign an IP address
assign_ip() {
  local ip=$1
  echo "$ip" >> "$ASSIGNED_IPS_FILE"
}

# Function to release an IP address
release_ip() {
  local ip=$1
  sed -i "/^$ip$/d" "$ASSIGNED_IPS_FILE"
}

# Add a New Client (Modified to use IP address management)
add_client() {
  CLIENT_NAME=$1
  DEVICE_NAME=$2

  if [ -z "$DEVICE_NAME" ]; then
    echo "Device name is required!"
    echo "Usage: $0 add <client_name> <device_name>"
    exit 1
  fi

  if [[ ! "$CLIENT_NAME" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo "Invalid client name!"
    exit 1
  fi

  if [[ ! "$DEVICE_NAME" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo "Invalid device name!"
    exit 1
  fi

  # Find a free IP address
  if ! FREE_IP=$(find_free_ip); then
    echo "No free IP addresses available!"
    exit 1
  fi

  # Assign the IP address
  assign_ip "$FREE_IP"

  mkdir -p $CLIENT_DIR
  wg genkey | tee $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_private.key | wg pubkey > $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_public.key

  CLIENT_PRIVATE_KEY=$(cat $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_private.key)
  CLIENT_PUBLIC_KEY=$(cat $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_public.key)
  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
  detect_public_ip

  # Add the client to the server's configuration
  echo "[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $FREE_IP/32" >> $WG_CONFIG

  systemctl restart wg-quick@$WG_INTERFACE

  CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}.conf"
  cat > $CLIENT_CONFIG <<EOL
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $FREE_IP/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = 10.10.0.0/16
PersistentKeepalive = 25
EOL

  chmod 600 $CLIENT_CONFIG
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Client '$CLIENT_NAME' Device '$DEVICE_NAME' added with IP '$FREE_IP'" | tee -a $LOG_FILE
  echo "Client '$CLIENT_NAME' Device '$DEVICE_NAME' added! Config saved at: $CLIENT_CONFIG"

  # Generate QR code for mobile clients (not needed but cool)
  qrencode -t ansiutf8 < $CLIENT_CONFIG
}

# Remove a Client (Modified to release IP address)
remove_client() {
  CLIENT_NAME=$1
  DEVICE_NAME=$2

  if ! grep -q "$(cat $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_public.key 2>/dev/null)" $WG_CONFIG; then
    echo "Client '$CLIENT_NAME' Device '$DEVICE_NAME' not found!"
    exit 1
  fi

  # Extract the IP address from the WireGuard config
  CLIENT_IP=$(grep "$(cat $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_public.key)" "$WG_CONFIG" -A 1 | tail -n 1 | awk '{print $3}' | sed 's/\/32//')

  sed -i "/$(cat $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_public.key)/,+1d" $WG_CONFIG
  rm -f $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_private.key $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}_public.key $CLIENT_DIR/${CLIENT_NAME}_${DEVICE_NAME}.conf
  systemctl restart wg-quick@$WG_INTERFACE

  # Release the IP address
  release_ip "$CLIENT_IP"

  echo "$(date '+%Y-%m-%d %H:%M:%S') - Client '$CLIENT_NAME' Device '$DEVICE_NAME' removed (IP: $CLIENT_IP released)" | tee -a $LOG_FILE
  echo "Client '$CLIENT_NAME' Device '$DEVICE_NAME' has been removed."
}

#Script Commands (very essential)
if [ "$1" == "install" ]; then
  install_wireguard
  generate_server_keys
  configure_server
  configure_firewall
  echo "WireGuard installed and configured!"
  echo "Don't forget to restart the WireGuard service after installation:"
  echo "sudo systemctl restart wg-quick@$WG_INTERFACE"
elif [ "$1" == "add" ]; then
  add_client $2 $3 # Pass both client and device name
elif [ "$1" == "remove" ]; then
  remove_client $2 $3 # Pass both client and device name
elif [ "$1" == "log" ]; then
  log_connections
elif [ "$1" == "service" ]; then
  setup_service
else
  echo "Usage: $0 {install|add|remove|log|service}"
fi

# Function to check if the network is up
check_network() {
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

  # Ping Google's DNS to check connectivity
  if ping -c 3 -W 2 8.8.8.8 > /dev/null 2>&1; then
    echo "$TIMESTAMP - Network is UP" | tee -a $LOG_FILE
  else
    echo "$TIMESTAMP - Network is DOWN" | tee -a $LOG_FILE
  fi
}

# Run network check every 30 seconds
monitor_network() {
  echo "Starting network monitoring..."
  while true; do
    check_network
    sleep 30
  done
}

# If the script is called with 'network', start network monitoring
if [ "$1" == "network" ]; then
  monitor_network
fi
