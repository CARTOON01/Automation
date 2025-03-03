#!/bin/bash

# Define variables
WG_INTERFACE="wg0"
LOCAL_NETWORK_INTERFACE="wlan0"  # Local network interface (Wi-Fi)
INTERNET_INTERFACE="eth0"       # Internet-facing interface (Ethernet)

# Get the Raspberry Pi's IP address and subnet from the wg0.conf file
RASPBERRY_PI_IP=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}' | cut -d'/' -f1)
LOCAL_SUBNET=$(grep "^Address = " /etc/wireguard/wg0.conf | awk '{print $3}')

# Extract the subnet base (10.10.X) from the RASPBERRY_PI_IP
SUBNET_BASE=$(echo "$RASPBERRY_PI_IP" | awk -F. '{print $1"."$2"."$3}')

DHCP_RANGE_START="$SUBNET_BASE.2" # DHCP range start
DHCP_RANGE_END="$SUBNET_BASE.254"   # DHCP range end
WIFI_SSID="Rasp4B"               # Wi-Fi network name (SSID)
WIFI_PASSWORD="1234567890"       # Wi-Fi password (WPA passphrase)

# Function to log messages
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Install required packages
install_packages() {
  log "Installing required packages..."
  sudo apt update
  sudo apt install -y hostapd isc-dhcp-server wireguard qrencode iptables-persistent
}

# Configure static IP for wlan0
configure_static_ip() {
  log "Configuring static IP for wlan0..."
  sudo sed -i '$a interface wlan0\nstatic ip_address='"$RASPBERRY_PI_IP"'/24\nnohook wpa_supplicant' /etc/dhcpcd.conf
}

# Configure DHCP server (isc-dhcp-server)
configure_dhcp() {
  log "Configuring DHCP server..."
  sudo tee /etc/dhcp/dhcpd.conf > /dev/null <<EOL
# /etc/dhcp/dhcpd.conf
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

# Configure Access Point (hostapd)
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
  sudo sed -i 's/#DAEMON_CONF=""/DAEMON_CONF="\/etc\/hostapd\/hostapd.conf"/g' /etc/default/hostapd
}

# Enable IP Forwarding
enable_ip_forwarding() {
  log "Enabling IP forwarding..."
  sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
  sudo sysctl -p /etc/sysctl.conf
}

# Configure NAT (iptables)
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

# Configure WireGuard Interface
configure_wireguard() {
  log "Configuring WireGuard interface..."
  # You'll need to manually copy the wg0.conf file to /etc/wireguard/
  # from the server.  This script assumes it's already there.
  sudo wg-quick up wg0
}

# Enable and restart services
enable_restart_services() {
  log "Enabling and restarting services..."
  sudo systemctl enable hostapd
  sudo systemctl enable isc-dhcp-server
  sudo systemctl restart hostapd
  sudo systemctl restart isc-dhcp-server
}

# Main script execution
install_packages
configure_static_ip
configure_dhcp
configure_hostapd
enable_ip_forwarding
configure_nat
configure_wireguard
enable_restart_services

log "Raspberry Pi configured as a WireGuard router!"
log "Remember to copy the wg0.conf file from the server to /etc/wireguard/"
