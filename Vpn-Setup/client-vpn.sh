#!/bin/bash

# ================================
# WireGuard Client Setup on Raspberry Pi
# ================================

# Variables
WG_INTERFACE="wg0"
LOCAL_NETWORK_INTERFACE="wlan0"  # Local Wi-Fi network interface
INTERNET_INTERFACE="eth0"        # Internet-facing interface (Ethernet)

# Extract Raspberry Pi IP from WireGuard config
RASPBERRY_PI_IP=$(awk -F' = ' '/Address/ {print $2}' /etc/wireguard/wg0.conf | cut -d'/' -f1)
LOCAL_SUBNET=$(awk -F' = ' '/Address/ {print $2}' /etc/wireguard/wg0.conf)

# Extract subnet base (e.g., 10.10.1)
SUBNET_BASE=$(echo "$RASPBERRY_PI_IP" | awk -F. '{print $1"."$2"."$3}')

DHCP_RANGE_START="$SUBNET_BASE.2"
DHCP_RANGE_END="$SUBNET_BASE.254"

WIFI_SSID="Rasp4B"     # Wi-Fi SSID
WIFI_PASSWORD="1234567890"  # Wi-Fi Password

# Logging function
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Exit script on error
set -e

# ================================
# Step 1: Install Required Packages
# ================================
install_packages() {
  log "Installing required packages..."
  sudo apt update
  sudo apt install -y hostapd isc-dhcp-server wireguard qrencode iptables-persistent
}

# ================================
# Step 2: Configure Static IP for wlan0
# ================================
configure_static_ip() {
  log "Configuring static IP for wlan0..."
  sudo sed -i "/interface wlan0/d" /etc/dhcpcd.conf
  sudo sed -i "/static ip_address=/d" /etc/dhcpcd.conf
  echo -e "interface wlan0\nstatic ip_address=${RASPBERRY_PI_IP}/24\nnohook wpa_supplicant" | sudo tee -a /etc/dhcpcd.conf
  sudo systemctl restart dhcpcd
}

# ================================
# Step 3: Configure DHCP Server
# ================================
configure_dhcp() {
  log "Configuring DHCP server..."
  sudo tee /etc/dhcp/dhcpd.conf > /dev/null <<EOL
INTERFACESv4="wlan0";
ddns-update-style none;
option domain-name "Rasp4B.router";
option domain-name-servers 1.1.1.1, 8.8.8.8;
default-lease-time 600;
max-lease-time 7200;
authoritative;
log-facility local7;
subnet $LOCAL_SUBNET netmask 255.255.255.0 {
    range $DHCP_RANGE_START $DHCP_RANGE_END;
    option subnet-mask 255.255.255.0;
    option broadcast-address $SUBNET_BASE.255;
    option routers $RASPBERRY_PI_IP;
}
EOL
  sudo sed -i 's/INTERFACESv4=""/INTERFACESv4="wlan0"/g' /etc/default/isc-dhcp-server
}

# ================================
# Step 4: Configure Wi-Fi Access Point
# ================================
configure_hostapd() {
  log "Configuring Access Point..."
  sudo tee /etc/hostapd/hostapd.conf > /dev/null <<EOL
interface=wlan0
ssid=$WIFI_SSID
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$WIFI_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOL
  sudo sed -i 's|#DAEMON_CONF=""|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
}

# ================================
# Step 5: Enable IP Forwarding
# ================================
enable_ip_forwarding() {
  log "Enabling IP forwarding..."
  sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
  sudo sysctl -p /etc/sysctl.conf
}

# ================================
# Step 6: Configure NAT (iptables)
# ================================
configure_nat() {
  log "Configuring NAT..."
  sudo iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -s "$LOCAL_SUBNET" -j MASQUERADE
  sudo iptables -A FORWARD -i $INTERNET_INTERFACE -o $LOCAL_NETWORK_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
  sudo iptables -A FORWARD -i $LOCAL_NETWORK_INTERFACE -o $INTERNET_INTERFACE -j ACCEPT
  sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"
  sudo tee /etc/rc.local > /dev/null <<EOL
#!/bin/sh -e
iptables-restore < /etc/iptables.ipv4.nat
exit 0
EOL
  sudo chmod +x /etc/rc.local
}

# ================================
# Step 7: Configure WireGuard Interface
# ================================
configure_wireguard() {
  log "Configuring WireGuard interface..."
  if [ -f "/etc/wireguard/wg0.conf" ]; then
    sudo wg-quick down wg0 || true  # Ensure previous instance is stopped
    sudo wg-quick up wg0
  else
    log "Error: /etc/wireguard/wg0.conf not found!"
    exit 1
  fi
}

# ================================
# Step 8: Enable & Restart Services
# ================================
enable_restart_services() {
  log "Enabling and restarting services..."
  sudo systemctl enable hostapd isc-dhcp-server
  sudo systemctl restart hostapd isc-dhcp-server
  sudo systemctl restart wg-quick@wg0
}

# ================================
# Main Execution
# ================================
log "Starting Raspberry Pi VPN Client Setup..."

install_packages
configure_static_ip
configure_dhcp
configure_hostapd
enable_ip_forwarding
configure_nat
configure_wireguard
enable_restart_services

log "Raspberry Pi successfully configured as a WireGuard VPN router!"
log "Ensure that the wg0.conf file is properly set up before running this script."
