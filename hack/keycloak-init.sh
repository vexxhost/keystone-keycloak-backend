#!/bin/bash

# Start Keycloak in the background
/opt/keycloak/bin/kc.sh start-dev &

echo "Waiting for Keycloak to start..."
until /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password admin 2>/dev/null; do
  sleep 3
done

echo "Keycloak is ready"

echo "Configure kcadm"

/opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user "${KEYCLOAK_ADMIN}" \
  --password "${KEYCLOAK_ADMIN_PASSWORD}"

EXIST=$(/opt/keycloak/bin/kcadm.sh get realms/test1 2>/dev/null || true)

if echo "$EXIST" | grep -q '"realm"'; then
    echo "Realm 'test1' already exists, skipping."
else
    echo "Create 'test1' realm"
    /opt/keycloak/bin/kcadm.sh create realms -s realm=test1 -s enabled=true
fi

EXIST=$(/opt/keycloak/bin/kcadm.sh get realms/test2 2>/dev/null || true)

if echo "$EXIST" | grep -q '"realm"'; then
    echo "Realm 'test2' already exists, skipping."
else
    echo "Create 'test2' realm"
    /opt/keycloak/bin/kcadm.sh create realms -s realm=test2 -s enabled=true
fi

echo "Disable SSL requirement"

/opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE
/opt/keycloak/bin/kcadm.sh update realms/test1 -s sslRequired=NONE
/opt/keycloak/bin/kcadm.sh update realms/test2 -s sslRequired=NONE

echo "SSL requirement disabled"

echo "Create Keycloak client for Keystone integration in 'test1' realm"

/opt/keycloak/bin/kcadm.sh create clients \
  -r test1 \
  -s clientId=keystone-client \
  -s enabled=true \
  -s protocol=openid-connect \
  -s publicClient=false \
  -s serviceAccountsEnabled=true \
  -s standardFlowEnabled=false \
  -s directAccessGrantsEnabled=false \
  -s authorizationServicesEnabled=false

CLIENT_ID=$(/opt/keycloak/bin/kcadm.sh get clients \
  -r test1 \
  -q clientId=keystone-client \
  --fields id \
  | grep '"id"' | sed 's/.*"id" : "\(.*\)".*/\1/')

/opt/keycloak/bin/kcadm.sh update clients/$CLIENT_ID \
  -r test1 \
  -s 'secret=12345abcdeFGHIJKLMN67890qrstuvWXYZ'

/opt/keycloak/bin/kcadm.sh add-roles \
  -r test1 \
  --uusername service-account-keystone-client \
  --cclientid realm-management \
  --rolename view-users

echo "Environment setup complete. Keeping container running."
wait
