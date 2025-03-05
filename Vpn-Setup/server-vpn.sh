#!/bin/bash

# Define script path
SCRIPT_PATH="/usr/local/bin/server-vpn"

# Copy this script to /usr/local/bin/server-vpn and make it executable
if [[ "$0" != "$SCRIPT_PATH" ]]; then
    echo "Installing server-vpn command..."
    sudo cp "$0" "$SCRIPT_PATH"
    sudo chmod +x "$SCRIPT_PATH"
    echo "server-vpn command installed! You can now use:"
    echo "  sudo server-vpn install"
    echo "  sudo server-vpn add <client_name>"
    echo "  sudo server-vpn remove <client_name>"
    exit 0
fi

# WireGuard Interface
WG_INTERFACE="wg0"
WG_CONFIG="/etc/wireguard/wg0.conf"
CLIENT_DIR="/etc/wireguard/clients"
SUBNET_FILE="/etc/wireguard/used_subnets"
LOG_FILE="/var/log/wireguard_server.log"

# Install WireGuard
install_wireguard() {
    echo "Installing WireGuard..."
    sudo apt update && sudo apt install -y wireguard qrencode
}

# Generate Server Keys
generate_server_keys() {
    [[ ! -f "/etc/wireguard/server_private.key" ]] && wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
}

# Detect Public IP
detect_public_ip() {
    SERVER_IP=$(curl -s ifconfig.me)
    echo "Detected Public IP: $SERVER_IP"
}

# Get Next Available Subnet
get_next_subnet() {
    touch "$SUBNET_FILE"
    local last_octet=1
    local max_octet=254

    while [ $last_octet -le $max_octet ]; do
        local subnet="10.10.${last_octet}.0/24"
        if ! grep -q "$subnet" "$SUBNET_FILE"; then
            echo "$subnet" >> "$SUBNET_FILE"
            echo "$subnet"
            return
        fi
        ((last_octet++))
    done
    echo ""
}

# Configure WireGuard Server
configure_server() {
    detect_public_ip
    echo "Configuring WireGuard Server..."
    cat > $WG_CONFIG <<EOL
[Interface]
PrivateKey = $(cat /etc/wireguard/server_private.key)
Address = 10.10.0.1/16
ListenPort = 51820
SaveConfig = true
PostUp = iptables -t nat -A POSTROUTING -o eth0 -s 10.10.0.0/16 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -s 10.10.0.0/16 -j MASQUERADE
EOL
}

# Enable IP Forwarding & Firewall Rules
configure_firewall() {
    echo "Configuring Firewall..."
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
    sudo ufw allow 51820/udp
}

# Add a New Client
add_client() {
    CLIENT_NAME=$1
    [[ -z "$CLIENT_NAME" ]] && { echo "Usage: server-vpn add <client_name>"; exit 1; }

    CLIENT_SUBNET=$(get_next_subnet)
    [[ -z "$CLIENT_SUBNET" ]] && { echo "No more subnets available!"; exit 1; }

    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)

    CLIENT_IP=$(echo "$CLIENT_SUBNET" | awk -F. '{print $1"."$2"."$3".1"}')

    echo "[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_SUBNET" >> $WG_CONFIG

    systemctl restart wg-quick@$WG_INTERFACE

    mkdir -p $CLIENT_DIR
    CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}.conf"
    cat > $CLIENT_CONFIG <<EOL
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/24
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOL

    chmod 600 "$CLIENT_CONFIG"
    echo "Client '$CLIENT_NAME' added! Config saved at: $CLIENT_CONFIG"
}

# Remove a Client
remove_client() {
    CLIENT_NAME=$1
    [[ -z "$CLIENT_NAME" ]] && { echo "Usage: server-vpn remove <client_name>"; exit 1; }

    CLIENT_CONFIG="$CLIENT_DIR/${CLIENT_NAME}.conf"
    [[ ! -f "$CLIENT_CONFIG" ]] && { echo "Client not found!"; exit 1; }

    CLIENT_PUBLIC_KEY=$(grep -A1 "\[Interface\]" "$CLIENT_CONFIG" | grep "PrivateKey" | awk '{print $3}' | wg pubkey)
    sed -i "/$CLIENT_PUBLIC_KEY/d" "$WG_CONFIG"

    rm -f "$CLIENT_CONFIG"
    systemctl restart wg-quick@$WG_INTERFACE
    echo "Client '$CLIENT_NAME' removed!"
}

# List Clients
list_clients() {
    ls "$CLIENT_DIR"
}

# Uninstall WireGuard
uninstall_wireguard() {
    echo "Uninstalling WireGuard..."
    sudo systemctl stop wg-quick@$WG_INTERFACE
    sudo apt remove --purge -y wireguard
    sudo rm -rf /etc/wireguard
}

# Apply Updates to Existing Configurations
update_server() {
    echo "Updating WireGuard configurations..."
    systemctl restart wg-quick@$WG_INTERFACE
}

# Main Execution
case "$1" in
    install)
        install_wireguard
        generate_server_keys
        configure_server
        configure_firewall
        echo "WireGuard Server Installed!"
        ;;
    add)
        add_client $2
        ;;
    remove)
        remove_client $2
        ;;
    list)
        list_clients
        ;;
    uninstall)
        uninstall_wireguard
        ;;
    update)
        update_server
        ;;
    *)
        echo "Usage: server-vpn {install|add <client_name>|remove <client_name>|list|uninstall|update}"
        exit 1
        ;;
esac
