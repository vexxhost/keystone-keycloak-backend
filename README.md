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

To test with bulk users and groups, you can enable test data loading using
environment variables:

```bash
$ KEYCLOAK_LOAD_DATA=true docker compose up -d
```

Available environment variables:

| Variable | Default | Description |
| ---------- | --------- | ------------- |
| `KEYCLOAK_LOAD_DATA` | `false` | Set to `true` to enable bulk data creation |
| `KEYCLOAK_USER_COUNT` | `1000` | Number of test users to create |
| `KEYCLOAK_GROUP_COUNT` | `1000` | Number of test groups to create |

Example with custom counts:

```bash
$ KEYCLOAK_LOAD_DATA=true KEYCLOAK_USER_COUNT=500 KEYCLOAK_GROUP_COUNT=100 docker compose up -d
```

**Note:** Creating large numbers of users and groups can take a long time
(10-15 minutes for 1000 users + 1000 groups). Monitor progress with:

```bash
$ docker compose logs -f keycloak
```
