#!/bin/bash

# Define variables
WG_INTERFACE="wg0"
LOCAL_NETWORK_INTERFACE="eth0"  # Force local network interface to eth0
INTERNET_INTERFACE="eth0"       # Replace with your internet-facing interface

# Get the Raspberry Pi's IP address and subnet from the wg0.conf file
RASPBERRY_PI_IP=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}' | cut -d'/' -f1)
LOCAL_SUBNET=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}')

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

# Configure DHCP Server (isc-dhcp-server)
configure_dhcp() {
  echo "Configuring isc-dhcp-server..."
  sudo apt install -y isc-dhcp-server

  # Configure DHCP server
  cat > /etc/dhcp/dhcpd.conf <<EOL
subnet $LOCAL_SUBNET netmask 255.255.255.0 {
  range 10.10.100.10 10.10.100.254;
  option routers $RASPBERRY_PI_IP;
  option domain-name-servers 1.1.1.1; # Or your preferred DNS server
  default-lease-time 43200; # 12 hours
  max-lease-time 86400;   # 24 hours
}
EOL

  # Tell DHCP server to listen on the correct interface
  sudo sed -i "s/INTERFACESv4=\"\"/INTERFACESv4=\"$LOCAL_NETWORK_INTERFACE\"/g" /etc/default/isc-dhcp-server

  sudo systemctl restart isc-dhcp-server
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

# Get the Raspberry Pi's IP address and subnet from the wg0.conf file
RASPBERRY_PI_IP=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}' | cut -d'/' -f1)
LOCAL_SUBNET=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}')

configure_nat
configure_dhcp
configure_wireguard

echo "Raspberry Pi configured as a WireGuard router!"
echo "Remember to copy the wg0.conf file from the server to /etc/wireguard/"
