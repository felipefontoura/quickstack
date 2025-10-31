#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

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
  else
    print_warning "No SSH authorized_keys found for root user. Please add SSH keys manually to /home/docker/.ssh/authorized_keys"
  fi

  # Backup config file
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

  # Configure SSH daemon for security
  cat <<EOF >/etc/ssh/sshd_config
# ===============================
# SSH Secure & Safe Config
# ===============================

# Include additional configurations (maintains compatibility with modern distros)
Include /etc/ssh/sshd_config.d/*.conf

# Default port — can be changed to reduce scan noise
Port 22

# Allow IPv4 and IPv6 (ensures compatibility in any environment)
AddressFamily any
Protocol 2

# Server keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key

# Logs
SyslogFacility AUTH
LogLevel VERBOSE

# Login control
LoginGraceTime 30
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 5
MaxSessions 5

# Authentication
PubkeyAuthentication yes
PasswordAuthentication yes        # <--- Kept as "yes" to avoid initial lockout
PermitEmptyPasswords no
ChallengeResponseAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
UsePAM yes

# After validating public key access, can be changed to "no"
# PasswordAuthentication no

# Redirects and tunneling
AllowAgentForwarding no
AllowTcpForwarding yes
X11Forwarding no
PermitTTY yes

# Banner and MOTD
PrintMotd no

# Keepalive (maintains active sessions even with NAT/firewall)
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes

# Allow users (adapt to your reality)
# Includes root (with key) and the default VM user (e.g.: ubuntu, ec2-user, debian)
AllowUsers root docker

# Strong but compatible encryption
KexAlgorithms +curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers +chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs +hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Additional security
LoginGraceTime 30
MaxStartups 10:30:100
PermitUserEnvironment no
Compression no
EOF

  # Test the SSH configuration before reloading
  if ! sshd -t -f /etc/ssh/sshd_config; then
    print_error "SSH configuration test failed! Restoring backup..."
    mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    exit 1
  fi

  print_success "SSH configuration test passed."
  print_warning "⚠️ SSH will now reload with new security settings."
  print_warning "⚠️ Keep this session open and test login in a NEW terminal before closing!"

  systemctl reload ssh
  print_success "SSH security configured."
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
  ufw allow http
  ufw allow https
  ufw --force enable

  print_success "Firewall configured"
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

# --- Main Installation Process ---
print_info "Starting System Installation..."

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

# Setup firewall
setup_firewall

# Setup automated maintenance
setup_automated_maintenance

# Verify security settings
verify_security_settings

# Final cleanup
apt-get autoremove -y >/dev/null 2>&1
apt-get clean >/dev/null 2>&1

print_success "System installation completed successfully!"
