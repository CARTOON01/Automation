#!/bin/bash

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
  cat > $WG_CONFIG <<EOL
[Interface]
PrivateKey = $(cat /etc/wireguard/server_private.key)
Address = 10.0.0.1/24
ListenPort = 51820
SaveConfig = true
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT
EOL
}

# Enable Firewall & Start WireGuard
configure_firewall() {
  sudo ufw allow 51820/udp
  sudo systemctl enable wg-quick@$WG_INTERFACE
  sudo systemctl start wg-quick@$WG_INTERFACE
}

# Add a New Client
add_client() {
  CLIENT_NAME=$1
  CLIENT_IP="10.0.0.$((RANDOM % 100 + 2))/32"

  if [[ ! "$CLIENT_NAME" =~ ^[a-zA-Z0-9_]+$ ]]; then
    echo "Invalid client name!"
    exit 1
  fi

  mkdir -p $CLIENT_DIR
  wg genkey | tee $CLIENT_DIR/${CLIENT_NAME}_private.key | wg pubkey > $CLIENT_DIR/${CLIENT_NAME}_public.key

  CLIENT_PRIVATE_KEY=$(cat $CLIENT_DIR/${CLIENT_NAME}_private.key)
  CLIENT_PUBLIC_KEY=$(cat $CLIENT_DIR/${CLIENT_NAME}_public.key)
  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
  detect_public_ip

  echo "[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP" >> $WG_CONFIG

  systemctl restart wg-quick@$WG_INTERFACE

  CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}.conf"
  cat > $CLIENT_CONFIG <<EOL
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = ${CLIENT_IP%/*}
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOL

  chmod 600 $CLIENT_CONFIG
  echo "$(date '+%Y-%m-%d %H:%M:%S') - Client '$CLIENT_NAME' added" | tee -a $LOG_FILE
  echo "Client '$CLIENT_NAME' added! Config saved at: $CLIENT_CONFIG"

  # Generate QR code for mobile clients (not needed but I saw this being cool)
  qrencode -t ansiutf8 < $CLIENT_CONFIG
}

# Remove a Client
remove_client() {
  CLIENT_NAME=$1
  if ! grep -q "$(cat $CLIENT_DIR/${CLIENT_NAME}_public.key 2>/dev/null)" $WG_CONFIG; then
    echo "Client '$CLIENT_NAME' not found!"
    exit 1
  fi

  sed -i "/$(cat $CLIENT_DIR/${CLIENT_NAME}_public.key)/,+1d" $WG_CONFIG
  rm -f $CLIENT_DIR/${CLIENT_NAME}_private.key $CLIENT_DIR/${CLIENT_NAME}_public.key $CLIENT_DIR/${CLIENT_NAME}.conf
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
ExecStart=/bin/bash /usr/local/bin/vpn-setup log
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
