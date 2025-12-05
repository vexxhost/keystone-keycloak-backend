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
        help="Keycloak admin username (for Direct Grant authentication)",
    ),
    cfg.StrOpt(
        "password",
        secret=True,
        help="Keycloak admin password (for Direct Grant authentication)",
    ),
    cfg.StrOpt(
        "client_secret_key",
        secret=True,
        help="Client secret for Service Account authentication. "
        "When provided, Service Account authentication will be used "
        "instead of Direct Grant.",
    ),
    cfg.StrOpt(
        "realm_name",
        help="Keycloak realm name",
    ),
    cfg.StrOpt(
        "user_realm_name",
        help="Keycloak user realm name (for Direct Grant authentication only). "
        "Specifies the realm where admin user credentials exist. "
        "If not specified, defaults to realm_name.",
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
