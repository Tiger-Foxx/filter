#!/bin/bash
# =============================================================================
# FoxEngine NFQUEUE Setup Script
# =============================================================================
# Topology:
#   [Client 10.10.1.10] <---> [FILTREUR] <---> [Serveur 10.10.2.20]
#   
#   Client side:  enp66s0f0 (10.10.1.1/24)
#   Server side:  enp4s0f1  (10.10.2.1/24)
#
# Usage:
#   ./setup_nfqueue.sh          # Configure NFQUEUE (Client->Server filtered)
#   ./setup_nfqueue.sh clean    # Remove all rules
#   ./setup_nfqueue.sh status   # Show current rules
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Network configuration
CLIENT_NET="10.10.1.0/24"
CLIENT_IP="10.10.1.10"
SERVER_NET="10.10.2.0/24"
SERVER_IP="10.10.2.20"

CLIENT_IFACE="enp66s0f0"  # Interface côté client
SERVER_IFACE="enp4s0f1"   # Interface côté serveur

QUEUE_NUM=0

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root (sudo)${NC}"
    exit 1
fi

show_status() {
    echo -e "${BLUE}>>> Current iptables FORWARD rules:${NC}"
    iptables -L FORWARD -n -v --line-numbers
    echo ""
    echo -e "${BLUE}>>> NFQUEUE rules:${NC}"
    iptables -L FORWARD -n -v | grep -i "NFQUEUE" || echo "  (none)"
}

clean_rules() {
    echo -e "${YELLOW}>>> Removing FoxEngine NFQUEUE rules...${NC}"
    
    # Remove ALL occurrences of NFQUEUE rules (loop until none left)
    local count=0
    
    # Remove Client->Server NFQUEUE rules
    while iptables -D FORWARD -s ${CLIENT_NET} -d ${SERVER_NET} -j NFQUEUE --queue-num ${QUEUE_NUM} 2>/dev/null; do
        ((count++))
    done
    
    # Remove Server->Client ACCEPT rules
    while iptables -D FORWARD -s ${SERVER_NET} -d ${CLIENT_NET} -j ACCEPT 2>/dev/null; do
        ((count++))
    done
    
    # Also remove any generic NFQUEUE rules on queue 0 (safety)
    while iptables -D FORWARD -j NFQUEUE --queue-num ${QUEUE_NUM} 2>/dev/null; do
        ((count++))
    done
    
    while iptables -D INPUT -j NFQUEUE --queue-num ${QUEUE_NUM} 2>/dev/null; do
        ((count++))
    done
    
    if [ $count -gt 0 ]; then
        echo -e "${GREEN}>>> Removed ${count} rule(s)!${NC}"
    else
        echo -e "${BLUE}>>> No rules to remove.${NC}"
    fi
}

setup_rules() {
    echo -e "${BLUE}>>> Setting up FoxEngine NFQUEUE rules...${NC}"
    echo ""
    echo -e "Topology:"
    echo -e "  [Client ${CLIENT_IP}] <---> [${CLIENT_IFACE}] FILTREUR [${SERVER_IFACE}] <---> [Serveur ${SERVER_IP}]"
    echo ""
    
    # Clean existing rules first
    clean_rules 2>/dev/null || true
    
    # Enable IP forwarding (required for routing)
    echo -e "${BLUE}>>> Enabling IP forwarding...${NC}"
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # =========================================================================
    # RULE 1: Server -> Client = ACCEPT (responses, no filtering)
    # =========================================================================
    echo -e "${GREEN}>>> [1/2] Server->Client: ACCEPT (no filtering)${NC}"
    iptables -I FORWARD -s ${SERVER_NET} -d ${CLIENT_NET} -j ACCEPT
    
    # =========================================================================
    # RULE 2: Client -> Server = NFQUEUE (filtered by FoxEngine)
    # =========================================================================
    echo -e "${GREEN}>>> [2/2] Client->Server: NFQUEUE (filtered)${NC}"
    iptables -I FORWARD -s ${CLIENT_NET} -d ${SERVER_NET} -j NFQUEUE --queue-num ${QUEUE_NUM}
    
    echo ""
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN}   NFQUEUE SETUP COMPLETE!${NC}"
    echo -e "${GREEN}=============================================${NC}"
    echo ""
    echo -e "Traffic flow:"
    echo -e "  ${YELLOW}Client -> Server:${NC} Inspected by FoxEngine (Queue ${QUEUE_NUM})"
    echo -e "  ${GREEN}Server -> Client:${NC} Accepted (no inspection)"
    echo ""
    echo -e "${YELLOW}Now start FoxEngine:${NC}"
    echo -e "  sudo ./bin/fox-engine"
    echo ""
    echo -e "${YELLOW}To remove rules later:${NC}"
    echo -e "  sudo ./setup_nfqueue.sh clean"
    echo -e "${GREEN}=============================================${NC}"
}

# Parse arguments
case "${1,,}" in
    clean|remove|reset)
        clean_rules
        ;;
    status|show)
        show_status
        ;;
    help|-h|--help)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  (none)    Setup NFQUEUE rules (Client->Server filtered)"
        echo "  clean     Remove all FoxEngine iptables rules"
        echo "  status    Show current iptables FORWARD rules"
        echo "  help      Show this help message"
        ;;
    *)
        setup_rules
        ;;
esac
