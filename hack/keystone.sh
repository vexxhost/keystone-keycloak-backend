#!/bin/bash -xe

cat << EOF | sudo tee /etc/keystone/keystone.conf
[database]
connection = mysql+pymysql://keystone:password@database/keystone

[identity]
domain_specific_drivers_enabled = true
EOF

mkdir -p /etc/keystone/domains

cat << EOF | sudo tee /etc/keystone/domains/keystone.keycloak.conf
[identity]
driver = keycloak

[keycloak]
server_url = http://keycloak:8080
realm_name = test1
client_id = keystone-client
client_secret_key = 12345abcdeFGHIJKLMN67890qrstuvWXYZ
debug = false
EOF

cat << EOF | sudo tee /etc/keystone/domains/keystone.keycloak-legacy.conf
[identity]
driver = keycloak

[keycloak]
server_url = http://keycloak:8080
username = admin
password = admin
realm_name = test2
user_realm_name = master
client_id = admin-cli
debug = false
EOF

/var/lib/openstack/bin/keystone-manage fernet_setup \
  --keystone-user keystone \
  --keystone-group keystone

sudo -u keystone /var/lib/openstack/bin/keystone-manage db_sync
sudo -u keystone /var/lib/openstack/bin/keystone-manage bootstrap \
  --bootstrap-project-name admin \
  --bootstrap-username admin \
  --bootstrap-password admin \
  --bootstrap-region-id RegionOne \
  --bootstrap-admin-url http://localhost:15000/v3 \
  --bootstrap-public-url http://localhost:15000/v3 \
  --bootstrap-internal-url http://localhost:15000/v3

# Create a domains for Keycloak
python <<EOF
import uuid

from keystone import exception
from keystone.common import provider_api
from keystone.common import sql
import keystone.conf
from keystone.server import backends

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs

domains = [
  {
    'id': uuid.uuid4().hex,
    'name': 'keycloak',
    'enabled': True,
  },
  {
    'id': uuid.uuid4().hex,
    'name': 'keycloak-legacy',
    'enabled': True,
  }
]

keystone.conf.configure()
sql.initialize()
backends.load_backends()

CONF(project='keystone')

for domain in domains:
  try:
    PROVIDERS.resource_api.create_domain(
      domain_id=domain['id'],
      domain=domain,
    )
  except keystone.exception.Conflict:
    pass
EOF

exec uwsgi \
  --wsgi-file /var/lib/openstack/bin/keystone-wsgi-public \
  --lazy \
  --uid keystone \
  --gid keystone \
  --http-socket 0.0.0.0:5000
