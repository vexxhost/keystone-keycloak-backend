#!/bin/bash
set -e

KCADM="/opt/keycloak/bin/kcadm.sh"
SERVER_URL="http://localhost:8080"
CLIENT_SECRET="12345abcdeFGHIJKLMN67890qrstuvWXYZ"

# Start Keycloak in the background
/opt/keycloak/bin/kc.sh start-dev &

echo "Waiting for Keycloak to start..."
until $KCADM config credentials \
  --server "$SERVER_URL" \
  --realm master \
  --user admin \
  --password admin 2>/dev/null; do
  sleep 3
done

echo "Keycloak is ready"

# Configure kcadm with admin credentials
$KCADM config credentials \
  --server "$SERVER_URL" \
  --realm master \
  --user "${KEYCLOAK_ADMIN}" \
  --password "${KEYCLOAK_ADMIN_PASSWORD}"

# Disable SSL requirement on master realm for dev environment
echo "Disabling SSL requirement on master realm"
$KCADM update realms/master -s sslRequired=NONE

# Function to create a realm if it doesn't exist
create_realm() {
  local realm_name="$1"

  if $KCADM get "realms/$realm_name" &>/dev/null; then
    echo "Realm '$realm_name' already exists, skipping."
  else
    echo "Creating realm '$realm_name'"
    $KCADM create realms -s "realm=$realm_name" -s enabled=true -s sslRequired=NONE
  fi

  # Configure realm settings (update even if realm existed to ensure correct config)
  echo "Configuring realm '$realm_name' (sslRequired=NONE, accessTokenLifespan=60)"
  $KCADM update "realms/$realm_name" -s sslRequired=NONE -s accessTokenLifespan=60
}

# Function to setup client for Keystone integration
setup_keystone_client() {
  local realm_name="$1"
  local client_id="keystone-client"

  # Check if client already exists
  local existing_client
  existing_client=$($KCADM get clients -r "$realm_name" -q "clientId=$client_id" --fields id 2>/dev/null || true)

  if echo "$existing_client" | grep -q '"id"'; then
    echo "Client '$client_id' already exists in realm '$realm_name', skipping creation."
    CLIENT_UUID=$(echo "$existing_client" | grep '"id"' | sed 's/.*"id" : "\(.*\)".*/\1/')
  else
    echo "Creating client '$client_id' in realm '$realm_name'"
    $KCADM create clients \
      -r "$realm_name" \
      -s "clientId=$client_id" \
      -s enabled=true \
      -s protocol=openid-connect \
      -s publicClient=false \
      -s serviceAccountsEnabled=true \
      -s standardFlowEnabled=false \
      -s directAccessGrantsEnabled=false \
      -s authorizationServicesEnabled=false

    CLIENT_UUID=$($KCADM get clients -r "$realm_name" -q "clientId=$client_id" --fields id \
      | grep '"id"' | sed 's/.*"id" : "\(.*\)".*/\1/')
  fi

  # Set client secret
  $KCADM update "clients/$CLIENT_UUID" -r "$realm_name" -s "secret=$CLIENT_SECRET"

  # Assign realm-management role to service account
  # Note: view-users role includes permissions to view users and groups
  local service_account="service-account-$client_id"
  echo "Assigning role 'view-users' to '$service_account' in realm '$realm_name'"
  $KCADM add-roles \
    -r "$realm_name" \
    --uusername "$service_account" \
    --cclientid realm-management \
    --rolename "view-users" 2>/dev/null || true
}

# Function to create bulk users and groups
create_bulk_data() {
  local realm_name="$1"
  local user_count="${2:-1000}"
  local group_count="${3:-1000}"

  echo "Creating $user_count users in realm '$realm_name'..."
  for i in $(seq 1 "$user_count"); do
    local username="testuser$(printf '%04d' $i)"

    $KCADM create users \
      -r "$realm_name" \
      -s "username=$username" \
      -s "email=$username@example.com" \
      -s "firstName=Test" \
      -s "lastName=User$i" \
      -s enabled=true 2>/dev/null || true

    # Progress indicator
    if [ $((i % 100)) -eq 0 ]; then
      echo "  Created $i/$user_count users..."
    fi
  done
  echo "Finished creating users."

  echo "Creating $group_count groups in realm '$realm_name'..."
  for i in $(seq 1 "$group_count"); do
    local groupname="testgroup$(printf '%03d' $i)"

    $KCADM create groups \
      -r "$realm_name" \
      -s "name=$groupname" 2>/dev/null || true

    # Progress indicator
    if [ $((i % 100)) -eq 0 ]; then
      echo "  Created $i/$group_count groups..."
    fi
  done
  echo "Finished creating groups."
}

# Create realms
create_realm "test1"
create_realm "test2"

# Setup Keystone client (only for test1 realm)
setup_keystone_client "test1"

# Create bulk test data if KEYCLOAK_LOAD_DATA is set to 'true'
if [ "${KEYCLOAK_LOAD_DATA}" = "true" ]; then
  create_bulk_data "test1" "${KEYCLOAK_USER_COUNT:-1000}" "${KEYCLOAK_GROUP_COUNT:-1000}"
else
  echo "Skipping bulk data creation (KEYCLOAK_LOAD_DATA=${KEYCLOAK_LOAD_DATA})"
fi

echo "Environment setup complete. Keeping container running."
wait
