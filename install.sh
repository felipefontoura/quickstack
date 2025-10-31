#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

REQUIRED_OS="Ubuntu"
REQUIRED_VERSION="24.04"
MIN_RAM_MB=1024
MIN_DISK_GB=10

# --- Aesthetics ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
ICON='\xF0\x9F\x9A\x80'
NC='\033[0m'

# --- Functions ---
print_message() {
  local color=$1
  local message=$2
  echo -e "${color}${ICON} ${message}${NC}"
}

print_error() {
  print_message "${RED}" "ERROR: $1"
}

print_warning() {
  print_message "${YELLOW}" "WARNING: $1"
}

print_success() {
  print_message "${GREEN}" "SUCCESS: $1"
}

print_info() {
  print_message "${BLUE}" "INFO: $1"
}

banner() {
  banner='
  ██████╗ ██╗   ██╗██╗ ██████╗██╗  ██╗███████╗████████╗ █████╗  ██████╗██╗  ██╗
  ██╔═══██╗██║   ██║██║██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
  ██║   ██║██║   ██║██║██║     █████╔╝ ███████╗   ██║   ███████║██║     █████╔╝ 
  ██║▄▄ ██║██║   ██║██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ 
  ╚██████╔╝╚██████╔╝██║╚██████╗██║  ██╗███████║   ██║   ██║  ██║╚██████╗██║  ██╗
  ╚══▀▀═╝  ╚═════╝ ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

  '

  echo -e "$banner"
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
  fi
}

check_os() {
  if ! command -v lsb_release >/dev/null 2>&1; then
    print_error "lsb_release command not found. Is this $REQUIRED_OS?"
    exit 1
  fi

  local os_name=$(lsb_release -is)
  local os_version=$(lsb_release -rs)

  if [[ "$os_name" != "$REQUIRED_OS" ]]; then
    print_error "This script requires $REQUIRED_OS (found $os_name)"
    exit 1
  fi

  if [[ "$os_version" != "$REQUIRED_VERSION" ]]; then
    print_warning "Script tested on $REQUIRED_OS $REQUIRED_VERSION (found $os_version). Proceeding anyway..."
  fi
}

check_resources() {
  local total_ram_mb=$(free -m | awk '/^Mem:/{print $2}')
  local total_disk_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')

  if ((total_ram_mb < MIN_RAM_MB)); then
    print_error "Insufficient RAM. Required: ${MIN_RAM_MB}MB, Found: ${total_ram_mb}MB"
    exit 1
  fi

  if ((total_disk_gb < MIN_DISK_GB)); then
    print_error "Insufficient disk space. Required: ${MIN_DISK_GB}GB, Found: ${total_disk_gb}GB"
    exit 1
  fi
}

check_params() {
  # Validate required parameters
  if [[ -z "$SERVER_IP" ]] || [[ -z "$DOMAIN" ]] || [[ -z "$EMAIL" ]]; then
    print_error "All parameters (SERVER_IP, DOMAIN, EMAIL) are required!"
    exit 1
  fi
}

handle_error() {
  local line_number=$1
  print_error "Script failed on line ${line_number}"
  print_error "Please check the logs above for more information"
  exit 1
}

# Set up error handling
trap 'handle_error ${LINENO}' ERR

# --- Main Installation Process ---
banner

print_info "Starting QuickStack..."

# Pre-flight checks
print_info "Performing pre-flight checks..."

check_root
check_os
check_resources
check_params

# System updates
print_info "Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install base
sudo apt-get install -y git jq

print_info "Cloning QuickStack..."
rm -rf ~/.local/share/quickstack
git clone https://github.com/felipefontoura/quickstack.git ~/.local/share/quickstack >/dev/null

QUICKSTACK_REF=${QUICKSTACK_REF:-"stable"}

if [[ $QUICKSTACK_REF != "main" ]]; then
  cd ~/.local/share/quickstack
  git fetch origin "$QUICKSTACK_REF" && git checkout "$QUICKSTACK_REF"
  cd - >/dev/null
fi

# Removing git repo
rm -rf ~/.local/share/quickstack/.git

# System installation
source ~/.local/share/quickstack/system.sh

# Install stacks
source ~/.local/share/quickstack/stacks.sh

print_info ""
print_info "🎉 Your services are now running:"
print_info "   • Portainer: https://portainer.$DOMAIN"
print_info "   • Postgres/PGVector: https://db.$DOMAIN"
print_info "   • N8N"
print_info "     • Editor: https://editor.n8n.$DOMAIN"
print_info "     • Webhooks: https://webhooks.n8n.$DOMAIN"
print_info "   • Evolution API: https://api.evolution.$DOMAIN"
print_info "   • Chatwoot: https://chatwoot.$DOMAIN"
print_info ""
print_info "🔒 Security features enabled:"
print_info "   • System hardening with kernel parameters"
print_info "   • SSH security configuration"
print_info "   • fail2ban intrusion prevention"
print_info "   • AppArmor mandatory access control"
print_info "   • AIDE file integrity monitoring"
print_info "   • Audit logging for Docker"
print_info "   • UFW firewall with Docker Swarm rules"
print_info "   • Automated security updates"
print_info ""
print_info "📋 Next steps:"
print_info "   1. Keep this session open and test login in a NEW terminal before closing!"
print_info "   2. Test Portainer at https://portainer.$DOMAIN"
print_info "   3. REBOOT THE SYSTEM to apply all security settings"
print_info ""
print_info "📊 System Information:"
print_info "   • Docker Version: $(docker --version)"
print_info "   • Kernel Version: $(uname -r)"
print_info "   • AppArmor Status: $(aa-status --enabled 2>/dev/null && echo 'Enabled' || echo 'Disabled')"
print_info "   • UFW Status: $(ufw status | grep Status)"
print_info "   • fail2ban Status: $(fail2ban-client status | grep "Number of jail:" 2>/dev/null || echo 'Not running')"
print_info ""
print_success "Installation complete! 🎯"
