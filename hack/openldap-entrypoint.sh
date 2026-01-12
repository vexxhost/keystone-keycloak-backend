#!/bin/bash
# Custom entrypoint that increases size limit after OpenLDAP starts

# Start OpenLDAP in the background using the original entrypoint
/opt/bitnami/scripts/openldap/entrypoint.sh /opt/bitnami/scripts/openldap/run.sh &
LDAP_PID=$!

# Wait for LDAP to be ready
echo "Waiting for OpenLDAP to start..."
for i in $(seq 1 30); do
    if ldapsearch -x -H ldap://localhost:1389 -b "dc=example,dc=com" -s base "(objectclass=*)" >/dev/null 2>&1; then
        echo "OpenLDAP is ready"
        break
    fi
    sleep 1
done

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
