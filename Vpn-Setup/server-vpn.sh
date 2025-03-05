#!/bin/bash

WG_INTERFACE="wg0"
WG_CONFIG="/etc/wireguard/wg0.conf"
CLIENT_DIR="/etc/wireguard/clients"
LOG_FILE="/var/log/wireguard_server.log"
SUBNET_FILE="/etc/wireguard/used_subnets"
BACKUP_DIR="/etc/wireguard/backup"

mkdir -p "$CLIENT_DIR" "$BACKUP_DIR"
touch "$LOG_FILE"

# Function to backup existing config
backup_config() {
  TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
  cp "$WG_CONFIG" "$BACKUP_DIR/wg0_$TIMESTAMP.conf"
  echo "Backup created: $BACKUP_DIR/wg0_$TIMESTAMP.conf" | tee -a "$LOG_FILE"
}

# Function to check and apply necessary updates
update_config() {
  echo "Checking for configuration updates..." | tee -a "$LOG_FILE"

  # Backup before modifying
  backup_config

  # Fetch new settings
  NEW_CONFIG=$(cat "$WG_CONFIG")

  # If file exists, check for differences
  if [ -f "$WG_CONFIG" ]; then
    DIFF_OUTPUT=$(diff "$BACKUP_DIR/wg0_$TIMESTAMP.conf" "$WG_CONFIG")
    
    if [ -z "$DIFF_OUTPUT" ]; then
      echo "No changes detected in configuration." | tee -a "$LOG_FILE"
    else
      echo "Applying necessary updates..." | tee -a "$LOG_FILE"
      systemctl restart wg-quick@"$WG_INTERFACE"
    fi
  fi
}

# Function to install WireGuard
install_wireguard() {
  echo "Installing WireGuard..." | tee -a "$LOG_FILE"
  sudo apt update && sudo apt install -y wireguard qrencode
}

# Function to remove WireGuard
uninstall_wireguard() {
  echo "Uninstalling WireGuard..." | tee -a "$LOG_FILE"
  sudo apt remove --purge -y wireguard qrencode
  rm -rf /etc/wireguard
}

# Function to add a new client
add_client() {
  CLIENT_NAME=$1
  if [[ -z "$CLIENT_NAME" ]]; then
    echo "Usage: $0 add <client_name>"
    exit 1
  fi

  CLIENT_PRIVATE_KEY=$(wg genkey)
  CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)

  CLIENT_IP="10.10.0.$((100 + RANDOM % 100))"

  echo "[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP/32" >> "$WG_CONFIG"

  systemctl restart wg-quick@"$WG_INTERFACE"

  CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}.conf"
  cat > "$CLIENT_CONFIG" <<EOL
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $(curl -s ifconfig.me):51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOL

  chmod 600 "$CLIENT_CONFIG"
  echo "Client '$CLIENT_NAME' added! Config saved at: $CLIENT_CONFIG" | tee -a "$LOG_FILE"
}

# Function to remove a client
remove_client() {
  CLIENT_NAME=$1
  if [[ -z "$CLIENT_NAME" ]]; then
    echo "Usage: $0 remove <client_name>"
    exit 1
  fi

  sed -i "/# $CLIENT_NAME/,/# End $CLIENT_NAME/d" "$WG_CONFIG"
  rm -f "$CLIENT_DIR/${CLIENT_NAME}.conf"
  systemctl restart wg-quick@"$WG_INTERFACE"
  echo "Client '$CLIENT_NAME' removed." | tee -a "$LOG_FILE"
}

# Main Execution
case "$1" in
  install)
    install_wireguard
    update_config
    echo "WireGuard Server Installed!"
    ;;
  add)
    add_client "$2"
    ;;
  remove)
    remove_client "$2"
    ;;
  uninstall)
    uninstall_wireguard
    ;;
  update)
    update_config
    ;;
  *)
    echo "Usage: $0 {install|add <client_name>|remove <client_name>|uninstall|update}"
    exit 1
    ;;
esac
