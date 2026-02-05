#!/bin/bash
# Custom entrypoint that increases size limit after OpenLDAP starts

# Start OpenLDAP in the background using the original entrypoint
/opt/bitnami/scripts/openldap/entrypoint.sh /opt/bitnami/scripts/openldap/run.sh &
LDAP_PID=$!

# Wait for LDAP to be ready
echo "Waiting for OpenLDAP to start..."
LDAP_READY=0
for i in $(seq 1 30); do
    if ldapsearch -x -H ldap://localhost:1389 -b "dc=example,dc=com" -s base "(objectclass=*)" >/dev/null 2>&1; then
        echo "OpenLDAP is ready"
        LDAP_READY=1
        break
    fi
    sleep 1
done

if [ "$LDAP_READY" -ne 1 ]; then
    echo "Error: OpenLDAP did not become ready within the timeout period." >&2
    if kill -0 "$LDAP_PID" 2>/dev/null; then
        kill "$LDAP_PID" 2>/dev/null || true
    fi
    wait "$LDAP_PID" 2>/dev/null || true
    exit 1
fi

# Increase size limit to 10000
echo "Increasing LDAP size limit to 10000..."
ldapmodify -Y EXTERNAL -H ldapi:/// << 'EOF' 2>/dev/null || true
dn: olcDatabase={-1}frontend,cn=config
changetype: modify
replace: olcSizeLimit
olcSizeLimit: 10000
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// << 'EOF' 2>/dev/null || true
dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcSizeLimit
olcSizeLimit: 10000
EOF

echo "Size limit configuration applied"

# Wait for the background process
wait $LDAP_PID
