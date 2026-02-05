# Keycloak backend for OpenStack Keystone

This is a Keycloak backend for OpenStack Keystone, it currently offers the
ability to use Keycloak as the following backends:

- Identity (users & groups)
- Soon: Assignment (projects, roles, etc)

The way this project is mean to be used is installed alongside Keystone with a
domain configured to use the Keycloak backend.

This allows you to use features such as OpenID Connect federation with the same domain but instead relying on `local` users instead of `federated` users

This means that you can control the enabled/disabled state of a user and update other attributes directly in Keycloak and they will be instantly reflected
inside of Keystone.

## Configuration

The driver is configured via Keystone's domain-specific configuration. Create a configuration file for your Keycloak domain (e.g., `/etc/keystone/domains/keystone.keycloak.conf`):

### Connection Options

| Option | Default | Required | Description |
| ------ | ------- | -------- | ----------- |
| `server_url` | - | Yes | Keycloak server URL (e.g., `http://keycloak:8080`) |
| `realm_name` | - | Yes | Keycloak realm name containing users and groups |
| `client_id` | `admin-cli` | No | Keycloak client ID |
| `verify` | `True` | No | Verify SSL certificate. Set to `False` for self-signed certs |

### Authentication Methods

The driver supports two mutually exclusive authentication methods:

#### Service Account Authentication (Recommended)

Uses a Keycloak client with service account enabled. The client must have the `view-users` role from `realm-management`.

```ini
[identity]
driver = keycloak

[keycloak]
server_url = http://keycloak:8080
realm_name = test1
client_id = keystone-client
client_secret_key = 12345abcdeFGHIJKLMN67890qrstuvWXYZ
```

| Option | Description |
| ------ | ----------- |
| `client_id` | Client ID with service account enabled |
| `client_secret_key` | Client secret. When provided, Service Account auth is used |

#### Direct Grant Authentication

Uses admin username/password credentials. Useful when you cannot create a service account client.

```ini
[identity]
driver = keycloak

[keycloak]
server_url = http://keycloak:8080
realm_name = test1
client_id = admin-cli
username = admin
password = admin
user_realm_name = master
```

| Option | Description |
| ------ | ----------- |
| `username` | Admin username |
| `password` | Admin password |
| `user_realm_name` | Realm where admin credentials exist. Defaults to `realm_name` if not specified. Use `master` if authenticating with a Keycloak admin user |

## Testing

In order to test this project, you will need both Docker and Docker Compose
installed on your system.  You can bring up a test environment by running:

```bash
$ docker compose up -d
```

This will bring up a Keycloak instance and a Keystone instance, you can then
login to the Keystone instance with the following credentials:

- Username: `admin`
- Password: `admin`

You can then use the Keystone CLI to interact with the Keystone instance:

```bash
$ source hack/testrc
$ openstack user list
```

### Loading Test Data

The test environment supports two types of test data:

1. **Local data**: Users and groups created directly in Keycloak (prefix: `local-`)
2. **LDAP data**: Users and groups synced from OpenLDAP via federation (prefix: `ldap-`)

#### Local Keycloak Data

To create bulk users and groups directly in Keycloak:

```bash
$ KEYCLOAK_LOAD_LOCAL_DATA=true docker compose up -d
```

| Variable | Default | Description |
| ---------- | --------- | ------------- |
| `KEYCLOAK_LOAD_LOCAL_DATA` | `false` | Set to `true` to enable local bulk data creation |
| `KEYCLOAK_LOCAL_USER_COUNT` | `1000` | Number of local test users to create |
| `KEYCLOAK_LOCAL_GROUP_COUNT` | `1000` | Number of local test groups to create |

Example with custom counts:

```bash
$ KEYCLOAK_LOAD_LOCAL_DATA=true KEYCLOAK_LOCAL_USER_COUNT=500 KEYCLOAK_LOCAL_GROUP_COUNT=100 docker compose up -d
```

#### LDAP Federation Data

To enable LDAP user federation with OpenLDAP:

```bash
$ KEYCLOAK_LOAD_LDAP_DATA=true docker compose up -d
```

| Variable | Default | Description |
| ---------- | --------- | ------------- |
| `KEYCLOAK_LOAD_LDAP_DATA` | `false` | Set to `true` to enable LDAP federation |

This will:

- Configure Keycloak to federate users from the OpenLDAP container
- Set up group mapping to sync LDAP groups and memberships
- Trigger an initial full sync of users and groups

The OpenLDAP container is pre-populated with:

- 5000 users (`ldap-testuser0000` to `ldap-testuser4999`)
- 2 primary groups (`ldap-users1`, `ldap-users2`) with 1000 members each
- 100 test groups (`ldap-testgroup0000` to `ldap-testgroup0099`) with 50 members each

To regenerate the LDAP data with different content, run:

```bash
$ ./hack/openldap-bootstrap.sh
$ docker compose down -v && docker compose up -d
```

#### Combined Setup

You can enable both local and LDAP data simultaneously:

```bash
$ KEYCLOAK_LOAD_LOCAL_DATA=true KEYCLOAK_LOAD_LDAP_DATA=true docker compose up -d
```

**Note:** Creating large numbers of local users and groups can take a long time
(10-15 minutes for 1000 users + 1000 groups). Monitor progress with:

```bash
$ docker compose logs -f keycloak
```
