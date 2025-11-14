# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

from oslo_config import cfg

keycloak_group = cfg.OptGroup(
    name="keycloak",
    title="Options for Keycloak backend",
)

keycloak_opts = [
    cfg.StrOpt(
        "server_url",
        help="Keycloak server URL",
    ),
    cfg.StrOpt(
        "username",
        help="Keycloak admin username",
    ),
    cfg.StrOpt(
        "password",
        secret=True,
        help="Keycloak admin password",
    ),
    cfg.StrOpt(
        "realm_name",
        help="Keycloak realm name",
    ),
    cfg.StrOpt(
        "user_realm_name",
        help="Keycloak user realm name",
    ),
    cfg.StrOpt(
        "client_id",
        default="admin-cli",
        help="Keycloak client ID",
    ),
    cfg.BoolOpt(
        "verify",
        default=True,
        help="Verify SSL certificate",
    ),
]


def register_opts(conf):
    conf.register_group(keycloak_group)
    conf.register_opts(keycloak_opts, group=keycloak_group)
