#!/bin/bash

# Start Keycloak in the background
/opt/keycloak/bin/kc.sh start-dev &

# Wait for Keycloak to be ready
echo "Waiting for Keycloak to start..."
until /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password admin 2>/dev/null; do
  sleep 3
done

echo "Keycloak is ready, disable SSL..."

# Configure kcadm
/opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user "${KEYCLOAK_ADMIN}" \
  --password "${KEYCLOAK_ADMIN_PASSWORD}"

# Disable SSL requirement
/opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE

echo "SSL requirement disabled"

# Keep container running
wait
