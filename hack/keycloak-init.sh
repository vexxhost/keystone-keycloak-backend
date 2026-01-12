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

# Function to disable "always read from LDAP" on default attribute mappers
# This prevents Keycloak from querying LDAP for each user on every request
disable_always_read_from_ldap() {
  local realm_name="$1"
  local provider_id="$2"

  echo "Disabling 'always read from LDAP' on default mappers..."

  # Mappers that have always.read.value.from.ldap=true by default:
  # - first name, last name, modify date, creation date
  local mappers=("first name" "last name" "modify date" "creation date")

  for mapper_name in "${mappers[@]}"; do
    local mapper_id
    mapper_id=$($KCADM get components -r "$realm_name" \
      -q "name=$mapper_name" -q "parentId=$provider_id" --fields id 2>/dev/null \
      | grep '"id"' | head -1 | sed 's/.*"id" : "\(.*\)".*/\1/')

    if [ -n "$mapper_id" ]; then
      echo "  Updating mapper '$mapper_name' (id: $mapper_id)"
      # Fetch current config, modify it, and update (partial updates don't work with kcadm)
      local current_config
      current_config=$($KCADM get "components/$mapper_id" -r "$realm_name" 2>/dev/null)

      # Replace "true" with "false" for always.read.value.from.ldap and update
      echo "$current_config" | sed 's/"always.read.value.from.ldap" : \[ "true" \]/"always.read.value.from.ldap" : [ "false" ]/' \
        | $KCADM update "components/$mapper_id" -r "$realm_name" -f - 2>/dev/null || true
    fi
  done

  echo "Mapper configuration updated."
}

# Function to setup LDAP user federation
setup_ldap_federation() {
  local realm_name="$1"
  local ldap_host="${LDAP_HOST:-ldap}"
  local ldap_port="${LDAP_PORT:-1389}"
  local provider_name="ldap-provider"

  echo "Setting up LDAP user federation in realm '$realm_name'..."

  # Check if LDAP provider already exists
  local existing_provider
  existing_provider=$($KCADM get components -r "$realm_name" -q "name=$provider_name" --fields id 2>/dev/null || true)

  if echo "$existing_provider" | grep -q '"id"'; then
    echo "LDAP provider '$provider_name' already exists in realm '$realm_name', skipping creation."
    LDAP_PROVIDER_ID=$(echo "$existing_provider" | grep '"id"' | head -1 | sed 's/.*"id" : "\(.*\)".*/\1/')
  else
    echo "Creating LDAP provider '$provider_name' in realm '$realm_name'"

    # Create LDAP user storage provider
    $KCADM create components -r "$realm_name" \
      -s name="$provider_name" \
      -s providerId=ldap \
      -s providerType=org.keycloak.storage.UserStorageProvider \
      -s 'config.enabled=["true"]' \
      -s 'config.priority=["0"]' \
      -s 'config.editMode=["READ_ONLY"]' \
      -s 'config.syncRegistrations=["false"]' \
      -s 'config.vendor=["other"]' \
      -s "config.connectionUrl=[\"ldap://${ldap_host}:${ldap_port}\"]" \
      -s 'config.bindDn=["cn=serviceuser,ou=svcaccts,dc=example,dc=com"]' \
      -s 'config.bindCredential=["mysecret"]' \
      -s 'config.usersDn=["ou=users,dc=example,dc=com"]' \
      -s 'config.usernameLDAPAttribute=["cn"]' \
      -s 'config.rdnLDAPAttribute=["cn"]' \
      -s 'config.uuidLDAPAttribute=["entryUUID"]' \
      -s 'config.userObjectClasses=["inetOrgPerson, organizationalPerson"]' \
      -s 'config.authType=["simple"]' \
      -s 'config.searchScope=["1"]' \
      -s 'config.useTruststoreSpi=["ldapsOnly"]' \
      -s 'config.connectionPooling=["false"]' \
      -s 'config.connectionTimeout=["30000"]' \
      -s 'config.readTimeout=["30000"]' \
      -s 'config.pagination=["true"]' \
      -s 'config.fullSyncPeriod=["-1"]' \
      -s 'config.batchSizeForSync=["1000"]' \
      -s 'config.changedSyncPeriod=["600"]' \
      -s 'config.cachePolicy=["DEFAULT"]' \
      -s 'config.importEnabled=["true"]'

    # Get the created provider ID
    LDAP_PROVIDER_ID=$($KCADM get components -r "$realm_name" -q "name=$provider_name" --fields id \
      | grep '"id"' | head -1 | sed 's/.*"id" : "\(.*\)".*/\1/')
  fi

  echo "LDAP Provider ID: $LDAP_PROVIDER_ID"

  # Disable "always read from LDAP" on default mappers for better performance
  disable_always_read_from_ldap "$realm_name" "$LDAP_PROVIDER_ID"

  # Setup LDAP group mapper
  setup_ldap_group_mapper "$realm_name" "$LDAP_PROVIDER_ID"

  # Trigger full user sync
  echo "Triggering full LDAP user sync..."
  $KCADM create "user-storage/$LDAP_PROVIDER_ID/sync?action=triggerFullSync" -r "$realm_name" 2>/dev/null || true

  echo "LDAP federation setup complete."
}

# Function to setup LDAP group mapper
setup_ldap_group_mapper() {
  local realm_name="$1"
  local parent_id="$2"
  local mapper_name="ldap-group-mapper"

  echo "Setting up LDAP group mapper..."

  # Check if group mapper already exists
  local existing_mapper
  existing_mapper=$($KCADM get components -r "$realm_name" -q "name=$mapper_name" -q "parentId=$parent_id" --fields id 2>/dev/null || true)

  if echo "$existing_mapper" | grep -q '"id"'; then
    echo "Group mapper '$mapper_name' already exists, skipping creation."
    return
  fi

  echo "Creating LDAP group mapper '$mapper_name'"

  # Use JSON input to avoid shell escaping issues with config keys containing dots
  $KCADM create components -r "$realm_name" -f - << EOF
{
  "name": "$mapper_name",
  "providerId": "group-ldap-mapper",
  "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
  "parentId": "$parent_id",
  "config": {
    "groups.dn": ["ou=groups,dc=example,dc=com"],
    "group.name.ldap.attribute": ["cn"],
    "group.object.classes": ["groupOfNames"],
    "preserve.group.inheritance": ["false"],
    "membership.ldap.attribute": ["member"],
    "membership.attribute.type": ["DN"],
    "membership.user.ldap.attribute": ["cn"],
    "groups.ldap.filter": [""],
    "mode": ["READ_ONLY"],
    "user.roles.retrieve.strategy": ["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"],
    "memberof.ldap.attribute": ["memberOf"],
    "drop.non.existing.groups.during.sync": ["false"]
  }
}
EOF

  # Trigger group sync
  echo "Triggering LDAP group sync..."
  local mapper_id
  mapper_id=$($KCADM get components -r "$realm_name" -q "name=$mapper_name" --fields id \
    | grep '"id"' | head -1 | sed 's/.*"id" : "\(.*\)".*/\1/')

  $KCADM create "user-storage/$parent_id/mappers/$mapper_id/sync?direction=fedToKeycloak" -r "$realm_name" 2>/dev/null || true

  echo "LDAP group mapper setup complete."
}

# Function to create bulk users and groups
create_bulk_data() {
  local realm_name="$1"
  local user_count="${2:-1000}"
  local group_count="${3:-1000}"

  echo "Creating $user_count users in realm '$realm_name'..."
  for i in $(seq 1 "$user_count"); do
    local username="local-testuser$(printf '%04d' $i)"

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
    local groupname="local-testgroup$(printf '%03d' $i)"

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

# Create bulk test data if KEYCLOAK_LOAD_LOCAL_DATA is set to 'true'
if [ "${KEYCLOAK_LOAD_LOCAL_DATA}" = "true" ]; then
  create_bulk_data "test1" "${KEYCLOAK_LOCAL_USER_COUNT:-1000}" "${KEYCLOAK_LOCAL_GROUP_COUNT:-1000}"
else
  echo "Skipping local bulk data creation (KEYCLOAK_LOAD_LOCAL_DATA=${KEYCLOAK_LOAD_LOCAL_DATA})"
fi

# Setup LDAP federation if KEYCLOAK_LOAD_LDAP_DATA is set to 'true'
if [ "${KEYCLOAK_LOAD_LDAP_DATA}" = "true" ]; then
  setup_ldap_federation "test1"
else
  echo "Skipping LDAP federation setup (KEYCLOAK_LOAD_LDAP_DATA=${KEYCLOAK_LOAD_LDAP_DATA})"
fi

echo "Environment setup complete. Keeping container running."
wait
