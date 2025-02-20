#!/bin/bash
#Ensure to include comments in the script to explain the purpose of each function and variable.
# Just for documentation purposes :)

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

# Ensure log file exists
touch $LOG_FILE && chmod 600 $LOG_FILE

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

# Detect Public IP
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
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -s 10.10.0.0/16 -j MASQUERADE
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -s 10.10.0.0/16 -j MASQUERADE
EOL
}

# Enable Firewall & Start WireGuard
configure_firewall() {
  sudo ufw allow 51820/udp
  sudo systemctl enable wg-quick@$WG_INTERFACE
  sudo systemctl start wg-quick@$WG_INTERFACE
}

# Function to get the next available subnet
get_next_subnet() {
  local last_octet=1   # Starting subnet (10.10.1.0/24)
  local max_octet=254  # Maximum subnet (10.10.254.0/24)

  while [ $last_octet -le $max_octet ]; do
    local subnet="10.10.${last_octet}.0/24"
    if ! grep -q "AllowedIPs = $subnet" "$WG_CONFIG"; then
      echo "$subnet"
      return
    fi
    ((last_octet++))
  done

  echo "" # No more subnets available
  return
}

# Add a New Client (Simplified for single command)
add_client() {
  CLIENT_NAME=$1

  if [[ -z "$CLIENT_NAME" ]]; then
    echo "Client name is required!"
    echo "Usage: $0 add <client_name>"
    exit 1
  fi

  if [[ ! "$CLIENT_NAME" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo "Invalid client name!"
    exit 1
  fi

  # Determine the next available subnet
  NEXT_SUBNET=$(get_next_subnet)
  if [ -z "$NEXT_SUBNET" ]; then
    echo "No more subnets available!"
    exit 1
  fi
  CLIENT_SUBNET="$NEXT_SUBNET"

  mkdir -p $CLIENT_DIR

  # Generate keys and store them in variables
  CLIENT_PRIVATE_KEY=$(wg genkey)
  CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
  detect_public_ip

  # Add the client to the server's configuration
  echo "[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_SUBNET, 10.10.0.0/16" >> $WG_CONFIG

  systemctl restart wg-quick@$WG_INTERFACE

  # Determine the Raspberry Pi's IP address within the subnet
  RASPBERRY_PI_IP=$(echo "$CLIENT_SUBNET" | awk -F. '{print $1"."$2"."$3".1"}')

  # Create the client configuration file content directly
  CLIENT_CONFIG_CONTENT="[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $RASPBERRY_PI_IP/24
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25"

  CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}.conf"
  echo "$CLIENT_CONFIG_CONTENT" > "$CLIENT_CONFIG"
  chmod 600 "$CLIENT_CONFIG"

  echo "$(date '+%Y-%m-%d %H:%M:%S') - Client '$CLIENT_NAME' added with subnet '$CLIENT_SUBNET' (Raspberry Pi Router)" | tee -a $LOG_FILE
  echo "Client '$CLIENT_NAME' added! Config saved at: $CLIENT_CONFIG"
  echo "Please copy the configuration file to the Raspberry Pi."
}

# Remove a Client (Modified)
remove_client() {
  CLIENT_NAME=$1

  if [[ -z "$CLIENT_NAME" ]]; then
    echo "Client name is required!"
    echo "Usage: $0 remove <client_name>"
    exit 1
  fi

  if ! grep -q "$(cat $CLIENT_DIR/${CLIENT_NAME}.conf 2>/dev/null)" $WG_CONFIG; then
    echo "Client '$CLIENT_NAME' not found!"
    exit 1
  fi

  sed -i "/$(grep -B1 "$(cat $CLIENT_DIR/${CLIENT_NAME}.conf)" $WG_CONFIG | head -n 1 | awk '{print $3}')/,+1d" $WG_CONFIG
  rm -f $CLIENT_DIR/${CLIENT_NAME}.conf
  systemctl restart wg-quick@$WG_INTERFACE

  echo "$(date '+%Y-%m-%d %H:%M:%S') - Client '$CLIENT_NAME' removed" | tee -a $LOG_FILE
  echo "Client '$CLIENT_NAME' has been removed."
}

# Log Client Connections
log_connections() {
  echo "Logging WireGuard connections..."
  while true; do
    wg show $WG_INTERFACE latest-handshakes | while read -r line; do
      CLIENT_KEY=$(echo $line | awk '{print $1}')
      LAST_HANDSHAKE=$(echo $line | awk '{print $2}')
      CURRENT_TIME=$(date +%s)
      TIME_DIFF=$((CURRENT_TIME - LAST_HANDSHAKE))

      if [ "$TIME_DIFF" -lt 10 ]; then
        CLIENT_NAME=$(grep -B1 "$CLIENT_KEY" $WG_CONFIG | head -1 | awk '{print $2}')
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Client '$CLIENT_NAME' connected" | tee -a $LOG_FILE
      fi
    done
    sleep 10
  done
}

#Setup of Auto-Logging Services
setup_service() {
  cat > /etc/systemd/system/wg-log.service <<EOL
[Unit]
Description=WireGuard Client Connection Logger
After=network.target
[Service]
ExecStart=/bin/bash /usr/local/bin/server-vpn log
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOL

  sudo systemctl daemon-reload
  sudo systemctl enable wg-log.service
  sudo systemctl start wg-log.service
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
  add_client $2
elif [ "$1" == "remove" ]; then
  remove_client $2
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

# Run network check every 30 seconds (modify as needed)
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
