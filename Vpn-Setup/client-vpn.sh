#!/bin/bash

# Define variables
WG_INTERFACE="wg0"
LOCAL_NETWORK_INTERFACE="eth0"  # Force local network interface to eth0
INTERNET_INTERFACE="eth0"       # Replace with your internet-facing interface

# Function to log messages
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Install WireGuard
install_wireguard() {
  log "Installing WireGuard..."
  sudo apt update
  sudo apt install -y wireguard
}

# Enable IP Forwarding
enable_ip_forwarding() {
  log "Enabling IP forwarding..."
  sudo sysctl -w net.ipv4.ip_forward=1
  sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
}

# Configure NAT (Masquerading)
configure_nat() {
  log "Configuring NAT..."
  sudo iptables -t nat -A POSTROUTING -o "$INTERNET_INTERFACE" -s "$LOCAL_SUBNET" -j MASQUERADE
  # Allow forwarding to the VPN subnet
  sudo iptables -A FORWARD -i "$LOCAL_NETWORK_INTERFACE" -o "$WG_INTERFACE" -d 10.10.0.0/16 -j ACCEPT
  sudo iptables -A FORWARD -i "$WG_INTERFACE" -o "$LOCAL_NETWORK_INTERFACE" -s 10.10.0.0/16 -j ACCEPT
  # Allow forwarding between subnets
  sudo iptables -A FORWARD -i "$LOCAL_NETWORK_INTERFACE" -o "$WG_INTERFACE" -j ACCEPT
  sudo iptables -A FORWARD -i "$WG_INTERFACE" -o "$LOCAL_NETWORK_INTERFACE" -j ACCEPT
  # Make NAT and forwarding rules persistent
  sudo apt install -y iptables-persistent
  sudo netfilter-persistent save
}

# Configure WireGuard Interface
configure_wireguard() {
  log "Configuring WireGuard interface..."
  # Check if wg0 already exists
  if ip link show wg0 >/dev/null 2>&1; then
    log "wg0 interface already exists. Skipping wg-quick up wg0"
  else
    # You'll need to manually copy the wg0.conf file to /etc/wireguard/
    # from the server.  This script assumes it's already there.
    log "Bringing up wg0 interface..."
    sudo wg-quick up wg0
    if [ $? -ne 0 ]; then
      log "Error bringing up wg0 interface!"
      exit 1
    fi
  fi
}

# Main script execution
install_wireguard
enable_ip_forwarding

# Get the Raspberry Pi's IP address and subnet from the wg0.conf file
RASPBERRY_PI_IP=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}' | cut -d'/' -f1)
LOCAL_SUBNET=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}')

configure_nat
configure_wireguard

log "Raspberry Pi configured as a WireGuard router!"
log "Remember to copy the wg0.conf file from the server to /etc/wireguard/"
