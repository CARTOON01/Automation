#!/bin/bash

# WireGuard Interface
WG_INTERFACE="wg0"

# Network Interfaces
LOCAL_NETWORK_INTERFACE="wlan0"
INTERNET_INTERFACE="eth0"

# Config Paths
WG_CONFIG="/etc/wireguard/wg0.conf"
CLIENT_CONFIG="/etc/wireguard/client.conf"

# VPN Server Details
SERVER_IP="<YOUR_SERVER_IP>"
SERVER_USER="your-username"

# Log File
LOG_FILE="/var/log/wireguard_client.log"
touch $LOG_FILE && chmod 600 $LOG_FILE

# Fetch Assigned Subnet
get_client_subnet() {
  grep "Address" "$CLIENT_CONFIG" | awk '{print $3}' | cut -d'/' -f1
}

# Install WireGuard
install_wireguard() {
  echo "Installing WireGuard..." | tee -a $LOG_FILE
  sudo apt update
  sudo apt install -y wireguard
}

# Retrieve Configuration from Server
fetch_config() {
  echo "Fetching client configuration from server..." | tee -a $LOG_FILE
  scp "$SERVER_USER@$SERVER_IP:/etc/wireguard/clients/$(hostname).conf" $CLIENT_CONFIG
  chmod 600 $CLIENT_CONFIG
}

# Configure WireGuard
configure_wireguard() {
  sudo cp $CLIENT_CONFIG $WG_CONFIG
  sudo systemctl enable wg-quick@$WG_INTERFACE
  sudo systemctl restart wg-quick@$WG_INTERFACE
}

# Enable IP Forwarding & NAT
setup_routing() {
  CLIENT_IP=$(get_client_subnet)
  LOCAL_SUBNET="${CLIENT_IP%.*}.0/24"

  sudo sysctl -w net.ipv4.ip_forward=1
  sudo iptables -t nat -A POSTROUTING -s $LOCAL_SUBNET -o $INTERNET_INTERFACE -j MASQUERADE
}

# Monitor VPN Connection
monitor_connection() {
  while true; do
    if ! ping -c 3 -W 2 8.8.8.8 > /dev/null 2>&1; then
      echo "VPN Connection Lost! Restarting WireGuard..." | tee -a $LOG_FILE
      sudo systemctl restart wg-quick@$WG_INTERFACE
    fi
    sleep 30
  done
}

# Main Execution
case "$1" in
  install)
    install_wireguard
    fetch_config
    configure_wireguard
    setup_routing
    ;;
  start)
    configure_wireguard
    monitor_connection
    ;;
  *)
    echo "Usage: $0 {install|start}"
    exit 1
    ;;
esac
