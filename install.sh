#!/bin/bash

# QuickStack Production Setup Script
# Sets up Docker Swarm with Traefik and Portainer for VPS deployment

set -euo pipefail
IFS=$'\n\t'

# --- Constants ---
REQUIRED_OS="Ubuntu"
REQUIRED_VERSION="24.04"
MIN_RAM_MB=1024
MIN_DISK_GB=10

# --- Variables ---
LETSENCRYPT_EMAIL=""
PORTAINER_DOMAIN=""

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

show_usage() {
  cat <<EOF
Usage: $0 --email <email> --domain <domain> [OPTIONS]

QuickStack Production Setup Script
Sets up Docker Swarm with Traefik and Portainer for VPS deployment

Required Parameters:
  --email <email>         Email address for Let's Encrypt SSL certificates
  --domain <domain>       Domain for Portainer (e.g., portainer.yourdomain.com)

Options:
  --help, -h             Show this help message
  --skip-confirmation    Skip confirmation prompt (for automated deployments)

Examples:
  $0 --email admin@example.com --domain portainer.example.com
  $0 --email admin@example.com --domain portainer.example.com --skip-confirmation

Requirements:
  - $REQUIRED_OS $REQUIRED_VERSION
  - Minimum $MIN_RAM_MB MB RAM
  - Minimum $MIN_DISK_GB disk space
  - Root privileges

EOF
}

parse_arguments() {
  local skip_confirmation=false

  while [[ $# -gt 0 ]]; do
    case $1 in
    --email)
      LETSENCRYPT_EMAIL="$2"
      shift 2
      ;;
    --domain)
      PORTAINER_DOMAIN="$2"
      shift 2
      ;;
    --skip-confirmation)
      skip_confirmation=true
      shift
      ;;
    --help | -h)
      show_usage
      exit 0
      ;;
    *)
      print_error "Unknown option: $1"
      show_usage
      exit 1
      ;;
    esac
  done

  # Validate required parameters
  if [[ -z "$LETSENCRYPT_EMAIL" ]]; then
    print_error "Missing required parameter: --email"
    show_usage
    exit 1
  fi

  if [[ -z "$PORTAINER_DOMAIN" ]]; then
    print_error "Missing required parameter: --domain"
    show_usage
    exit 1
  fi

  # Validate email format
  if [[ ! "$LETSENCRYPT_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    print_error "Invalid email format: $LETSENCRYPT_EMAIL"
    exit 1
  fi

  # Validate domain format
  if [[ ! "$PORTAINER_DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$ ]]; then
    print_error "Invalid domain format: $PORTAINER_DOMAIN"
    exit 1
  fi

  # Show configuration and ask for confirmation if not skipped
  print_info "Configuration:"
  print_info "  Email: $LETSENCRYPT_EMAIL"
  print_info "  Portainer Domain: $PORTAINER_DOMAIN"

  if [[ "$skip_confirmation" == false ]]; then
    read -p "Continue with this configuration? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      print_info "Installation cancelled by user."
      exit 0
    fi
  else
    print_info "Skipping confirmation (automated mode)"
  fi
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

install_essential_packages() {
  print_info "Installing essential security packages..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ufw \
    fail2ban \
    curl \
    wget \
    gnupg \
    lsb-release \
    ca-certificates \
    apt-transport-https \
    software-properties-common \
    sysstat \
    auditd \
    audispd-plugins \
    unattended-upgrades \
    acl \
    apparmor \
    apparmor-utils \
    aide \
    rkhunter \
    logwatch \
    git \
    python3-pyinotify \
    chrony

  print_success "Essential packages installed"
}

configure_system_hardening() {
  print_info "Configuring system hardening..."

  # Configure AppArmor
  systemctl enable apparmor
  systemctl start apparmor

  # Initialize AIDE (file integrity monitoring)
  print_info "Initializing AIDE database (this may take a few minutes)..."
  aide --config=/etc/aide/aide.conf --init >/dev/null 2>&1 || true
  if [ -f /var/lib/aide/aide.db.new ]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  fi

  # Configure kernel parameters for security
  cat <<EOF >/etc/sysctl.d/99-security.conf
# Network security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Docker needs IPv4 forwarding
net.ipv4.ip_forward = 1

# System limits
fs.file-max = 1048576
kernel.pid_max = 65536
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_tw_reuse = 1
vm.max_map_count = 262144
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 2

# File system hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Additional network hardening
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

  sysctl -p /etc/sysctl.d/99-security.conf
  sysctl --system

  # Configure system limits
  cat <<EOF >/etc/security/limits.d/docker.conf
* soft nproc 10000
* hard nproc 10000
* soft nofile 1048576
* hard nofile 1048576
* soft core 0
* hard core 0
* soft stack 8192
* hard stack 8192
EOF

  print_success "System hardening configured"
}

configure_time_sync() {
  print_info "Configuring time synchronization..."

  # Stop and disable systemd-timesyncd
  systemctl stop systemd-timesyncd || true
  systemctl disable systemd-timesyncd || true

  # Enable and start chrony
  systemctl enable chrony.service || true
  systemctl start chrony.service

  print_success "Time synchronization configured"
}

configure_ssh_security() {
  print_info "Configuring SSH security..."

  # Create docker user if it doesn't exist
  if ! id "docker" &>/dev/null; then
    adduser --system --group --shell /bin/bash --home /home/docker --disabled-password docker
    usermod -aG docker docker
  fi

  # Setup SSH for docker user
  mkdir -p /home/docker/.ssh
  chown -R docker:docker /home/docker
  chmod 755 /home/docker

  # Copy root's authorized keys to docker user if they exist
  if [ -f /root/.ssh/authorized_keys ]; then
    cp /root/.ssh/authorized_keys /home/docker/.ssh/authorized_keys
    chown -R docker:docker /home/docker/.ssh
    chmod 700 /home/docker/.ssh
    chmod 600 /home/docker/.ssh/authorized_keys
  fi

  # Configure SSH daemon for security
  cat <<EOF >/etc/ssh/sshd_config
Include /etc/ssh/sshd_config.d/*.conf
Port 22
AddressFamily inet
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key
SyslogFacility AUTH
LogLevel VERBOSE
LoginGraceTime 30
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 10
MaxSessions 5
PubkeyAuthentication yes
HostbasedAuthentication no
IgnoreRhosts yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
AllowAgentForwarding no
AllowTcpForwarding yes
X11Forwarding no
PermitTTY yes
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
AllowUsers docker root
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF

  systemctl reload ssh
  print_success "SSH security configured"
}

configure_fail2ban() {
  print_info "Configuring fail2ban..."

  # Configure Docker filter
  cat <<EOF >/etc/fail2ban/filter.d/docker.conf
[Definition]
failregex = failed login attempt from
ignoreregex =
EOF

  # Configure jail settings
  cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 10
banaction = ufw
banaction_allports = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 10
bantime = 3600

[docker]
enabled = true
filter = docker
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban
  print_success "fail2ban configured"
}

configure_audit_logging() {
  print_info "Configuring audit logging..."

  cat <<EOF >/etc/audit/rules.d/audit.rules
# Docker daemon configuration
-w /usr/bin/dockerd -k docker
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /usr/lib/systemd/system/docker.service -k docker
-w /etc/default/docker -k docker
-w /etc/docker/daemon.json -k docker
-w /usr/bin/docker -k docker-bin
EOF

  # Reload audit rules
  auditctl -R /etc/audit/rules.d/audit.rules >/dev/null 2>&1 || true
  systemctl enable auditd
  systemctl restart auditd

  print_success "Audit logging configured"
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    print_info "Docker already installed. Version: $(docker --version)"
    return 0
  fi

  print_info "Installing Docker..."
  curl -fsSL https://get.docker.com -o get-docker.sh
  sh get-docker.sh
  rm get-docker.sh

  # Configure Docker daemon with security settings
  mkdir -p /etc/docker
  cat <<EOF >/etc/docker/daemon.json
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "icc": true,
    "live-restore": false,
    "no-new-privileges": true,
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    },
    "features": {
        "buildkit": true
    },
    "experimental": false,
    "default-runtime": "runc",
    "storage-driver": "overlay2",
    "metrics-addr": "127.0.0.1:9323",
    "builder": {
        "gc": {
            "enabled": true,
            "defaultKeepStorage": "20GB"
        }
    }
}
EOF

  # Test Docker configuration
  systemctl enable docker
  systemctl restart docker || {
    print_error "Docker failed to start. Logs:"
    journalctl -u docker.service --no-pager | tail -n 20
    exit 1
  }

  # Verify Docker configuration
  docker info | grep -E "Cgroup Driver|Storage Driver|Logging Driver" || true

  print_success "Docker installed and configured securely"
}

setup_swarm() {
  if docker info 2>/dev/null | grep -q "Swarm: active"; then
    print_info "Docker Swarm already initialized"
    return 0
  fi

  print_info "Initializing Docker Swarm..."
  docker swarm init

  print_success "Docker Swarm initialized"
}

create_networks_and_volumes() {
  print_info "Creating Docker networks and volumes..."

  # Create public network if it doesn't exist
  if ! docker network ls | grep -q "network_public"; then
    docker network create --driver overlay --attachable network_public
    print_success "Created network_public"
  else
    print_info "network_public already exists"
  fi

  # Create volumes
  local volumes=("volume_swarm_shared" "volume_swarm_certificates" "portainer_data")
  for vol in "${volumes[@]}"; do
    if ! docker volume ls | grep -q "$vol"; then
      docker volume create "$vol"
      print_success "Created volume $vol"
    else
      print_info "Volume $vol already exists"
    fi
  done
}

configure_traefik() {
  print_info "Configuring Traefik..."

  # Create Traefik configuration
  mkdir -p /opt/quickstack/traefik

  # Update Traefik config with user's email
  sed "s/example@example.com/$LETSENCRYPT_EMAIL/g" stacks/infra/traefik.yml >/opt/quickstack/traefik/traefik.yml

  print_success "Traefik configured with email: $LETSENCRYPT_EMAIL"
}

configure_portainer() {
  print_info "Configuring Portainer..."

  # Create Portainer configuration
  mkdir -p /opt/quickstack/portainer

  # Update Portainer config with user's domain
  sed "s/portainer.website.com/$PORTAINER_DOMAIN/g" stacks/infra/portainer.yml >/opt/quickstack/portainer/portainer.yml

  print_success "Portainer configured with domain: $PORTAINER_DOMAIN"
}

deploy_stacks() {
  print_info "Deploying Traefik..."
  docker stack deploy --prune --resolve-image always --compose-file /opt/quickstack/traefik/traefik.yml traefik

  print_info "Waiting for Traefik to be ready..."
  sleep 10

  print_info "Deploying Portainer..."
  docker stack deploy --prune --resolve-image always --compose-file /opt/quickstack/portainer/portainer.yml portainer

  print_success "Stacks deployed successfully"
}

setup_firewall() {
  print_info "Configuring firewall..."

  # Install ufw if not present
  if ! command -v ufw >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
  fi

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow ssh
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 2376/tcp # Docker daemon
  ufw allow 2377/tcp # Docker swarm management
  ufw allow 7946/tcp # Docker swarm communication
  ufw allow 7946/udp # Docker swarm communication
  ufw allow 4789/udp # Docker overlay networks
  ufw --force enable

  print_success "Firewall configured"
}

verify_deployment() {
  print_info "Verifying deployment..."

  local max_attempts=30
  local attempt=0

  while [[ $attempt -lt $max_attempts ]]; do
    if docker service ls | grep -q "traefik.*1/1"; then
      break
    fi

    ((attempt++))
    if [[ $attempt -eq $max_attempts ]]; then
      print_error "Traefik failed to start properly"
      docker service logs traefik_traefik --tail 20
      exit 1
    fi

    sleep 2
  done

  attempt=0
  while [[ $attempt -lt $max_attempts ]]; do
    if docker service ls | grep -q "portainer.*1/1"; then
      break
    fi

    ((attempt++))
    if [[ $attempt -eq $max_attempts ]]; then
      print_error "Portainer failed to start properly"
      docker service logs portainer_portainer --tail 20
      exit 1
    fi

    sleep 2
  done

  print_success "All services are running"
}

verify_security_settings() {
  print_info "Verifying security settings..."
  local failed=0

  # Check kernel parameters
  local params=(
    "kernel.unprivileged_bpf_disabled=1"
    "net.ipv4.conf.all.log_martians=0"
    "net.ipv4.ip_forward=1"
    "fs.protected_hardlinks=1"
    "fs.protected_symlinks=1"
  )

  for param in "${params[@]}"; do
    local name=${param%=*}
    local expected=${param#*=}
    local actual=$(sysctl -n "$name" 2>/dev/null || echo "NOT_FOUND")
    if [[ "$actual" != "$expected" ]]; then
      print_warning "Kernel parameter $name = $actual (expected $expected)"
      failed=1
    fi
  done

  # Check Docker settings
  if ! docker info 2>/dev/null | grep -q "Cgroup Driver: systemd"; then
    print_warning "Docker is not using systemd cgroup driver"
    failed=1
  fi

  # Check services
  local services=("docker" "fail2ban" "ufw" "auditd" "chrony")
  for service in "${services[@]}"; do
    if ! systemctl is-active --quiet "$service"; then
      print_warning "Service $service is not running"
      failed=1
    fi
  done

  # Check AIDE database
  if [ ! -f /var/lib/aide/aide.db ]; then
    print_warning "AIDE database not initialized"
    failed=1
  fi

  # Check UFW status
  if ! ufw status | grep -q "Status: active"; then
    print_warning "UFW firewall is not active"
    failed=1
  fi

  # Check SSH configuration
  if ! grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
    print_warning "SSH password authentication is not disabled"
    failed=1
  fi

  # Check AppArmor
  if ! apparmor_status | grep -q "apparmor module is loaded." 2>/dev/null; then
    print_warning "AppArmor is not loaded"
    failed=1
  fi

  if [[ $failed -eq 0 ]]; then
    print_success "Security verification passed"
  else
    print_warning "Some security checks failed. Please review the warnings above."
  fi

  return $failed
}

setup_automated_maintenance() {
  print_info "Setting up automated maintenance tasks..."

  # Docker log rotation
  cat <<EOF >/etc/logrotate.d/docker-logs
/var/lib/docker/containers/*/*.log {
  rotate 7
  daily
  compress
  size=100M
  missingok
  delaycompress
  copytruncate
}
EOF

  # Docker cleanup script
  cat <<'EOF' >/etc/cron.daily/docker-cleanup
#!/bin/bash
docker system prune -af --volumes
docker builder prune -af --keep-storage=20GB
EOF
  chmod +x /etc/cron.daily/docker-cleanup

  # Configure unattended-upgrades for automated security updates
  cat <<EOF >/etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
  "\${distro_id}:\${distro_codename}-security";
  "\${distro_id}ESMApps:\${distro_codename}-apps-security";
  "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

  print_success "Automated maintenance tasks configured"
}

create_management_script() {
  print_info "Creating management script..."

  cat <<'EOF' >/usr/local/bin/quickstack
#!/bin/bash
# QuickStack management script

case "$1" in
  "status")
    echo "=== Docker Swarm Status ==="
    docker node ls
    echo
    echo "=== Services Status ==="
    docker service ls
    echo
    echo "=== Stack Status ==="
    docker stack ls
    echo
    echo "=== Security Status ==="
    echo "UFW Status: $(ufw status | grep Status)"
    echo "fail2ban Status: $(fail2ban-client status | grep "Number of jail:" 2>/dev/null || echo 'Not running')"
    echo "AppArmor Status: $(aa-status --enabled 2>/dev/null && echo 'Enabled' || echo 'Disabled')"
    ;;
  "logs")
    if [[ -z "$2" ]]; then
      echo "Usage: quickstack logs <service_name>"
      echo "Available services:"
      docker service ls --format "table {{.Name}}"
      exit 1
    fi
    docker service logs "$2" --follow
    ;;
  "restart")
    if [[ -z "$2" ]]; then
      echo "Usage: quickstack restart <stack_name>"
      echo "Available stacks:"
      docker stack ls --format "table {{.Name}}"
      exit 1
    fi
    docker service update --force "${2}_${3:-$(docker service ls --filter "name=${2}_" --format "{{.Name}}" | head -1 | cut -d'_' -f2)}"
    ;;
  "update")
    echo "Updating all services..."
    docker service ls --format "{{.Name}}" | xargs -I {} docker service update --image "$(docker service inspect --format='{{.Spec.TaskTemplate.ContainerSpec.Image}}' {})" {}
    ;;
  "security-check")
    echo "Running security verification..."
    # Re-run security verification
    systemctl status docker fail2ban ufw auditd chrony --no-pager
    echo
    echo "Firewall status:"
    ufw status
    echo
    echo "Recent fail2ban activity:"
    fail2ban-client status sshd 2>/dev/null || echo "SSH jail not active"
    ;;
  *)
    echo "QuickStack Management Script"
    echo "Usage: quickstack <command>"
    echo
    echo "Commands:"
    echo "  status         - Show status of all services"
    echo "  logs           - Show logs for a specific service"
    echo "  restart        - Restart a specific service"
    echo "  update         - Update all services to latest images"
    echo "  security-check - Run security verification"
    ;;
esac
EOF

  chmod +x /usr/local/bin/quickstack
  print_success "Management script created at /usr/local/bin/quickstack"
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

# Parse command line arguments first
parse_arguments "$@"

print_message "${YELLOW}" "🚀 Starting QuickStack Installation..."

# Pre-flight checks
print_info "Performing pre-flight checks..."
check_root
check_os
check_resources

# System updates
print_info "Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install essential security packages
install_essential_packages

# Configure system hardening
configure_system_hardening

# Configure time synchronization
configure_time_sync

# Configure SSH security
configure_ssh_security

# Configure fail2ban
configure_fail2ban

# Configure audit logging
configure_audit_logging

# Install Docker
install_docker

# Setup Docker Swarm
setup_swarm

# Create networks and volumes
create_networks_and_volumes

# Configure services
configure_traefik
configure_portainer

# Setup firewall
setup_firewall

# Deploy stacks
deploy_stacks

# Verify deployment
verify_deployment

# Setup automated maintenance
setup_automated_maintenance

# Verify security settings
verify_security_settings

# Create management script
create_management_script

# Final cleanup
apt-get autoremove -y >/dev/null 2>&1
apt-get clean >/dev/null 2>&1

print_success "QuickStack installation completed successfully!"
print_info ""
print_info "🎉 Your services are now running:"
print_info "   • Traefik Dashboard: https://your-server-ip (check Docker service logs for auth)"
print_info "   • Portainer: https://$PORTAINER_DOMAIN"
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
print_info "   1. Point your DNS records to this server's IP address"
print_info "   2. Access Portainer at https://$PORTAINER_DOMAIN to complete setup"
print_info "   3. Use 'quickstack status' to monitor services"
print_info "   4. Use 'quickstack logs <service>' to view service logs"
print_info "   5. Use 'quickstack security-check' to verify security settings"
print_info "   6. REBOOT THE SYSTEM to apply all security settings"
print_info ""
print_info "📖 Service management:"
print_info "   • View status: quickstack status"
print_info "   • View logs: quickstack logs <service_name>"
print_info "   • Restart service: quickstack restart <stack_name>"
print_info "   • Update services: quickstack update"
print_info "   • Security check: quickstack security-check"
print_info ""
print_info "📊 System Information:"
print_info "   • Docker Version: $(docker --version)"
print_info "   • Kernel Version: $(uname -r)"
print_info "   • AppArmor Status: $(aa-status --enabled 2>/dev/null && echo 'Enabled' || echo 'Disabled')"
print_info "   • UFW Status: $(ufw status | grep Status)"
print_info "   • fail2ban Status: $(fail2ban-client status | grep "Number of jail:" 2>/dev/null || echo 'Not running')"
print_info ""
print_success "Installation complete! 🎯"
