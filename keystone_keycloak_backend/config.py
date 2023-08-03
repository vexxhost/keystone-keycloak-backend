# Copyright 2023 VEXXHOST, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

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
