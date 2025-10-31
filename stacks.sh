#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

replace_in_stacks() {
  local file="$1"
  local search_pattern="$2"
  local replacement_value="$3"
  local escaped_search
  local escaped_replace

  # Escape special regex characters: . * [ ] ^ $ \ / &
  escaped_search=$(printf '%s\n' "$search_pattern" | sed 's/[.*[\]^$\\\/&]/\\&/g')
  escaped_replace=$(printf '%s\n' "$replacement_value" | sed 's/[.*[\]^$\\\/&]/\\&/g')

  find ~/.local/share/quickstack/stacks/ -type f -name "${file}" -exec sed -i "s/${escaped_search}/${escaped_replace}/g" {} \;
}

wait_for_service() {
  local stack_name="$1"
  local timeout="${2:-300}"  # Default 5 minutes timeout
  local elapsed=0
  local interval=5

  print_info "Waiting for stack '${stack_name}' services to be ready..."

  while [ $elapsed -lt $timeout ]; do
    local total_services=$(docker stack services "${stack_name}" --format "{{.Name}}" 2>/dev/null | wc -l)
 
    if [ "$total_services" -eq 0 ]; then
      print_warning "No services found for stack '${stack_name}'. Waiting..."
      sleep $interval
      elapsed=$((elapsed + interval))
      continue
    fi

    local ready_services=$(docker stack services "${stack_name}" --format "{{.Replicas}}" 2>/dev/null | grep -cE "^([0-9]+)/\1$" || true)
 
    if [ "$ready_services" -eq "$total_services" ]; then
      print_success "All services in stack '${stack_name}' are ready (${ready_services}/${total_services})"
      return 0
    fi
 
    echo -n "."
    sleep $interval
    elapsed=$((elapsed + interval))
  done
 
  print_warning "Timeout waiting for stack '${stack_name}' services. Some services may not be ready yet."
  docker stack services "${stack_name}"
  return 1
}

wait_for_postgres() {
  local timeout="${1:-120}"  # Default 2 minutes timeout
  local elapsed=0
  local interval=5

  print_info "Waiting for PostgreSQL to accept connections..."

  while [ $elapsed -lt $timeout ]; do
    if docker exec -i $(docker ps -q -f name=postgres 2>/dev/null | head -n1) pg_isready -U postgres >/dev/null 2>&1; then
      print_success "PostgreSQL is ready and accepting connections"
      return 0
    fi
    echo -n "."
    sleep $interval
    elapsed=$((elapsed + interval))
  done

  print_warning "Timeout waiting for PostgreSQL to be ready"
  return 1
}

wait_for_redis() {
  local timeout="${1:-120}"  # Default 2 minutes timeout
  local elapsed=0
  local interval=5

  print_info "Waiting for Redis to accept connections..."

  while [ $elapsed -lt $timeout ]; do
    if docker exec -i $(docker ps -q -f name=redis 2>/dev/null | head -n1) redis-cli ping >/dev/null 2>&1; then
      print_success "Redis is ready and accepting connections"
      return 0
    fi
    echo -n "."
    sleep $interval
    elapsed=$((elapsed + interval))
  done

  print_warning "Timeout waiting for Redis to be ready"
  return 1
}

deploy_stack_via_api() {
  local stack_name="$1"
  local compose_file_path="$2"

  print_info "Deploying stack '${stack_name}' via Portainer API..."

  # Read the compose file content
  local full_path="$HOME/.local/share/quickstack/${compose_file_path}"
  if [ ! -f "$full_path" ]; then
    print_warning "Compose file not found: ${full_path}"
    return 1
  fi
 
  local stack_file_content=$(cat "$full_path")
 
  # Escape the stack file content for JSON
  local escaped_content=$(echo "$stack_file_content" | jq -Rs .)
 
  # Deploy stack via API using file content
  local response=$(curl -s -X POST "http://localhost:9000/api/stacks?type=1&method=string&endpointId=1" \
    -H "Authorization: Bearer ${PORTAINER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
      \"Name\": \"${stack_name}\",
      \"SwarmID\": \"$(docker info --format '{{.Swarm.Cluster.ID}}' 2>/dev/null)\",
      \"StackFileContent\": ${escaped_content}
    }")
 
  if echo "$response" | grep -q "Id"; then
    print_success "Stack '${stack_name}' deployed successfully via API"
    wait_for_service "${stack_name}"
  else
    print_warning "Failed to deploy stack '${stack_name}' via API"
    echo "Response: $response"
    return 1
  fi
}

init_docker_swarm() {
  docker swarm init --advertise-addr="${SERVER_IP}"
}

create_docker_network() {
  docker network create --driver=overlay network_public
}

deploy_infra() {
  # Adjust common params
  replace_in_stacks "traefik.yml" "example@example.com" "$EMAIL"
  replace_in_stacks "portainer.yml" "portainer.website.com" "portainer.${DOMAIN}"

  # Deploy Traefik
  docker stack deploy --prune --resolve-image always --compose-file ~/.local/share/quickstack/stacks/infra/traefik.yml traefik
  wait_for_service "traefik"

  # Deploy Portainer
  docker stack deploy --prune --resolve-image always --compose-file ~/.local/share/quickstack/stacks/infra/portainer.yml portainer
  wait_for_service "portainer"
}

init_portainer_admin() {
  local max_attempts=60
  local attempt=0

  print_info "Waiting for Portainer to be ready..."

  # Wait for Portainer API to be available
  while [ $attempt -lt $max_attempts ]; do
    if curl -s -f http://localhost:9000/api/status >/dev/null 2>&1; then
      print_success "Portainer API is ready"
      break
    fi
    echo -n "."
    sleep 5
    attempt=$((attempt + 1))
  done

  if [ $attempt -eq $max_attempts ]; then
    print_warning "Timeout waiting for Portainer API"
    return 1
  fi

  # Generate admin password
  export PORTAINER_ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

  print_info "Initializing Portainer admin user..."

  # Initialize admin user
  local response=$(curl -s -X POST http://localhost:9000/api/users/admin/init \
    -H "Content-Type: application/json" \
    -d "{\"Username\":\"admin\",\"Password\":\"${PORTAINER_ADMIN_PASSWORD}\"}")

  if echo "$response" | grep -q "Username"; then
    print_success "Portainer admin user initialized successfully"
    print_info "Admin credentials - Username: admin | Password: ${PORTAINER_ADMIN_PASSWORD}"
    
    # Save credentials to file
    cat > ~/.local/share/quickstack/portainer-credentials.txt <<EOF
Portainer Admin Credentials
============================
URL: https://portainer.${DOMAIN}
Username: admin
Password: ${PORTAINER_ADMIN_PASSWORD}
EOF
    print_success "Credentials saved to ~/.local/share/quickstack/portainer-credentials.txt"
  else
    print_warning "Failed to initialize admin user. It may already exist."
  fi
}

get_portainer_token() {
  print_info "Authenticating with Portainer API..."

  export PORTAINER_TOKEN=$(curl -s -X POST http://localhost:9000/api/auth \
    -H "Content-Type: application/json" \
    -d "{\"Username\":\"admin\",\"Password\":\"${PORTAINER_ADMIN_PASSWORD}\"}" | jq -r .jwt)

  if [ -z "$PORTAINER_TOKEN" ] || [ "$PORTAINER_TOKEN" = "null" ]; then
    print_warning "Failed to obtain Portainer token"
    return 1
  fi

  print_success "Successfully authenticated with Portainer"
}

deploy_db() {
  export POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

  # Deploy Postgres
  replace_in_stacks "postgres.yml" "POSTGRES_PASSWORD=secret" "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"
  replace_in_stacks "postgres.yml" "db.website.com" "db.${DOMAIN}"

  deploy_stack_via_api "postgres" "stacks/db/postgres.yml"

  # Wait for Postgres to be ready and accepting connections
  wait_for_postgres

  # Deploy Redis
  deploy_stack_via_api "redis" "stacks/db/redis.yml"

  # Wait for Redis to be ready and accepting connections
  wait_for_redis
}

deploy_n8n() {
  N8N_ENCRYPTION_KEY=$(openssl rand -base64 128 | tr -d "=+/")

  replace_in_stacks "n8n.yml" "N8N_ENCRYPTION_KEY=secret" "N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}"
  replace_in_stacks "n8n.yml" "DB_POSTGRESDB_PASSWORD=secret" "DB_POSTGRESDB_PASSWORD=${POSTGRES_PASSWORD}"
  replace_in_stacks "n8n.yml" "editor.n8n.website.com" "editor.n8n.${DOMAIN}"
  replace_in_stacks "n8n.yml" "webhooks.n8n.website.com" "webhooks.n8n.${DOMAIN}"

  # Create DB
  docker exec -it -u postgres $(docker ps -q -f name=postgres) psql -U postgres -c "CREATE DATABASE n8n;"

  # Deploy via API
  deploy_stack_via_api "n8n" "stacks/app/n8n.yml"
}

deploy_evolution_api() {
  EVOLUTION_API_KEY=$(openssl rand -base64 64 | tr -d "=+/")

  replace_in_stacks "evolution-api.yml" "AUTHENTICATION_API_KEY=secret" "AUTHENTICATION_API_KEY=${EVOLUTION_API_KEY}"
  replace_in_stacks "evolution-api.yml" "postgresql://postgres:secret@postgres:5432/evolution" "postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/evolution"
  replace_in_stacks "evolution-api.yml" "api.evolution.website.com" "api.evolution.${DOMAIN}"

  # Create DB
  docker exec -it -u postgres $(docker ps -q -f name=postgres) psql -U postgres -c "CREATE DATABASE evolution;"

  # Deploy via API
  deploy_stack_via_api "evolution" "stacks/app/evolution-api.yml"
}

deploy_typebot() {
  TYPEBOT_ENCRYPTION_SECRET=$(openssl rand -base64 32 | tr -d "=+/")

  replace_in_stacks "typebot.yml" "DATABASE_URL=postgresql://postgres:secret@postgres:5432/typebot" "DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/typebot"
  replace_in_stacks "typebot.yml" "ENCRYPTION_SECRET=secret" "ENCRYPTION_SECRET=${TYPEBOT_ENCRYPTION_SECRET}"
  replace_in_stacks "typebot.yml" "ADMIN_EMAIL=example@example.com" "ADMIN_EMAIL=${EMAIL}"
  replace_in_stacks "typebot.yml" "NEXT_PUBLIC_SMTP_FROM='Typebot' <no-reply@website.com>" "NEXT_PUBLIC_SMTP_FROM='Typebot' <no-reply@${DOMAIN}>"
  replace_in_stacks "typebot.yml" "builder.bot.website.com" "builder.bot.${DOMAIN}"
  replace_in_stacks "typebot.yml" "bot.website.com" "bot.${DOMAIN}"

  # Create DB
  docker exec -it -u postgres $(docker ps -q -f name=postgres) psql -U postgres -c "CREATE DATABASE typebot;"

  # Deploy via API
  deploy_stack_via_api "typebot" "stacks/app/typebot.yml"
}

deploy_chatwoot() {
  CHATWOOT_SECRET_KEY_BASE=$(openssl rand -base64 128 | tr -d "=+/")

  replace_in_stacks "chatwoot.yml" "SECRET_KEY_BASE=secret" "SECRET_KEY_BASE=${CHATWOOT_SECRET_KEY_BASE}"
  replace_in_stacks "chatwoot.yml" "POSTGRES_PASSWORD=secret" "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"
  replace_in_stacks "chatwoot.yml" "chatwoot.website.com" "chatwoot.${DOMAIN}"

  # Create DB
  docker exec -it -u postgres $(docker ps -q -f name=postgres) psql -U postgres -c "CREATE DATABASE chatwoot;"

  # Deploy via API
  deploy_stack_via_api "chatwoot" "stacks/app/chatwoot.yml"
}

deploy_rabbitmq() {
  RABBITMQ_ERLANG_COOKIE=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
  RABBITMQ_DEFAULT_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

  replace_in_stacks "rabbitmq.yml" "RABBITMQ_ERLANG_COOKIE=secret" "RABBITMQ_ERLANG_COOKIE=${RABBITMQ_ERLANG_COOKIE}"
  replace_in_stacks "rabbitmq.yml" "RABBITMQ_DEFAULT_PASS=secret" "RABBITMQ_DEFAULT_PASS=${RABBITMQ_DEFAULT_PASS}"
  replace_in_stacks "rabbitmq.yml" "rabbitmq.website.com" "rabbitmq.${DOMAIN}"

  # Deploy via API
  deploy_stack_via_api "rabbitmq" "stacks/app/rabbitmq.yml"
}

# --- Main Installation Process ---
print_info "Starting Stacks Installation..."
print_info ""
print_info "SERVER IP: $SERVER_IP"
print_info "DOMAIN: $DOMAIN"
print_info "EMAIL: $EMAIL"

init_docker_swarm
create_docker_network

deploy_infra
init_portainer_admin
get_portainer_token

deploy_db
deploy_n8n
deploy_evolution_api
deploy_typebot
deploy_chatwoot
deploy_rabbitmq

print_success "Stack installation completed successfully!"
