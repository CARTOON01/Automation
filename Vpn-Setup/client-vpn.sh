#!/bin/bash

# Define variables
WG_INTERFACE="wg0"
#LOCAL_NETWORK_INTERFACE="eth0"  # Force local network interface to eth0
#INTERNET_INTERFACE="eth0"       # Replace with your internet-facing interface

# Server details for automatic wg0.conf copy
SERVER_IP="your_server_ip"       # Replace with your server's IP address
SERVER_USER="your_server_user"     # Replace with your server username
SERVER_PASSWORD="your_server_password" # Replace with your server password (or use SSH keys)

# Function to detect the internet interface
detect_internet_interface() {
  INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
  echo "$INTERFACE"
}

# Function to detect the local network interface
detect_local_interface() {
  INTERNET=$(detect_internet_interface)
  ALL_INTERFACES=$(ip link show | awk '{print $2}' | tr -d :)
  for IFACE in $ALL_INTERFACES; do
    if [ "$IFACE" != "$INTERNET" ] && [ "$IFACE" != "lo" ]; then
      echo "$IFACE"
      return
    fi
  done
  echo "eth0" # Default to eth0 if detection fails
}

# Function to copy the wg0.conf file from the server
copy_wg0_conf() {
  echo "Copying wg0.conf from server..."
  scp "$SERVER_USER@$SERVER_IP:/etc/wireguard/clients/$CLIENT_NAME.conf" /tmp/wg0.conf
  if [ $? -eq 0 ]; then
    sudo mv /tmp/wg0.conf /etc/wireguard/wg0.conf
    echo "wg0.conf copied successfully!"
  else
    echo "Failed to copy wg0.conf. Please check your server credentials and client name."
    exit 1
  fi
}

# Install WireGuard
install_wireguard() {
  echo "Installing WireGuard..."
  sudo apt update
  sudo apt install -y wireguard
}

# Enable IP Forwarding
enable_ip_forwarding() {
  echo "Enabling IP forwarding..."
  sudo sysctl -w net.ipv4.ip_forward=1
  sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
}

# Configure NAT (Masquerading)
configure_nat() {
  echo "Configuring NAT..."
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

# Configure DHCP Server (dnsmasq)
configure_dhcp() {
  echo "Configuring DHCP server (dnsmasq)..."
  sudo apt install -y dnsmasq

  # Backup the original dnsmasq.conf
  sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig

  cat > /etc/dnsmasq.conf <<EOL
interface=$LOCAL_NETWORK_INTERFACE
dhcp-range=10.10.100.10,10.10.100.254,255.255.255.0,12h
dhcp-option=option:router,$RASPBERRY_PI_IP
dhcp-option=option:dns-server,1.1.1.1 # Use a public DNS server
EOL

  sudo systemctl restart dnsmasq
}

# Configure WireGuard Interface
configure_wireguard() {
  echo "Configuring WireGuard interface..."
  # You'll need to manually copy the wg0.conf file to /etc/wireguard/
  # from the server.  This script assumes it's already there.
  sudo wg-quick up wg0
}

# Main script execution
install_wireguard
enable_ip_forwarding

# Detect interfaces
INTERNET_INTERFACE=$(detect_internet_interface)
LOCAL_NETWORK_INTERFACE=$(detect_local_interface)
echo "Detected Internet Interface: $INTERNET_INTERFACE"
echo "Detected Local Network Interface: $LOCAL_NETWORK_INTERFACE"

# Copy wg0.conf from server
copy_wg0_conf

# Get the Raspberry Pi's IP address and subnet from the wg0.conf file
RASPBERRY_PI_IP=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}' | cut -d'/' -f1)
LOCAL_SUBNET=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}')

configure_nat
configure_dhcp
configure_wireguard

echo "Raspberry Pi configured as a WireGuard router!"
