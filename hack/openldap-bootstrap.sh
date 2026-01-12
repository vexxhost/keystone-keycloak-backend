#!/bin/bash
# OpenLDAP bootstrap script - generates LDIF with 5000 users and groups

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LDIF_PATH="$SCRIPT_DIR/openldap-users.ldif"

echo "OpenLDAP LDIF Generator"
echo "======================="
echo "Output: $LDIF_PATH"

cat > "$LDIF_PATH" << 'HEADER'
# Base DN
dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
dc: example
o: Example Inc

# Organizational Units
dn: ou=svcaccts,dc=example,dc=com
objectClass: organizationalUnit
ou: svcaccts

dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups

# Service account for LDAP binding
dn: cn=serviceuser,ou=svcaccts,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: serviceuser
sn: User
givenName: Service
mail: serviceuser@example.com
userPassword: mysecret
description: Service account for LDAP binding

HEADER

echo "Generating 5000 users..."
for i in $(seq 0 4999); do
    username=$(printf "ldap-testuser%04d" "$i")
    uid=$((20000 + i))

    cat >> "$LDIF_PATH" << EOF
dn: cn=${username},ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: ${username}
sn: User${i}
givenName: Test${i}
mail: ${username}@example.com
userPassword: mysecret
employeeNumber: ${uid}

EOF
done

echo "Generating primary user groups with members..."
# ldap-users1 group - first 1000 users (0-999) (max 1000 members per group for H2 DB performance compatibility)
cat >> "$LDIF_PATH" << 'EOF'
dn: cn=ldap-users1,ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: top
cn: ldap-users1
description: Primary group 1
EOF
for i in $(seq 0 999); do
    username=$(printf "ldap-testuser%04d" "$i")
    echo "member: cn=${username},ou=users,dc=example,dc=com" >> "$LDIF_PATH"
done
echo "" >> "$LDIF_PATH"

# ldap-users2 group - next 1000 users (1000-1999) (max 1000 members per group for H2 DB performance compatibility)
cat >> "$LDIF_PATH" << 'EOF'
dn: cn=ldap-users2,ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: top
cn: ldap-users2
description: Primary group 2
EOF
for i in $(seq 1000 1999); do
    username=$(printf "ldap-testuser%04d" "$i")
    echo "member: cn=${username},ou=users,dc=example,dc=com" >> "$LDIF_PATH"
done
echo "" >> "$LDIF_PATH"

echo "Generating 100 additional test groups..."
for i in $(seq 0 99); do
    groupname=$(printf "ldap-testgroup%04d" "$i")
    # Each group has 50 members
    cat >> "$LDIF_PATH" << EOF
dn: cn=${groupname},ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: top
cn: ${groupname}
description: Test group ${i}
EOF
    # Add 50 members per group (users i*50 to i*50+49)
    start=$((i * 50))
    for j in $(seq 0 49); do
        idx=$((start + j))
        if [ $idx -lt 5000 ]; then
            username=$(printf "ldap-testuser%04d" "$idx")
            echo "member: cn=${username},ou=users,dc=example,dc=com" >> "$LDIF_PATH"
        fi
    done
    echo "" >> "$LDIF_PATH"
done

echo ""
echo "Generated:"
wc -l "$LDIF_PATH" | awk '{print "  LDIF: " $1 " lines"}'
echo ""
echo "Contents:"
echo "  - 1 service account"
echo "  - 5000 users (ldap-testuser0000-ldap-testuser4999)"
echo "  - 2 primary groups (ldap-users1: 1000 members, ldap-users2: 1000 members)"
echo "  - 100 test groups (ldap-testgroup0000-ldap-testgroup0099, 50 members each)"
echo ""
echo "Service account:"
echo "  DN: cn=serviceuser,ou=svcaccts,dc=example,dc=com"
echo "  Password: mysecret"
echo ""
echo "Admin account:"
echo "  DN: cn=admin,dc=example,dc=com"
echo "  Password: adminpassword"
