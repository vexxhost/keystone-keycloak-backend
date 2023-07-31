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

from keystone import conf as keystone_conf
from keystone.identity.backends import base

from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

from keystone_keycloak_backend import conf as kkb_conf
from keystone_keycloak_backend import utils

READ_ONLY_ERROR_MESSAGE = "Keycloak does not support write operations"


class Driver(base.IdentityDriverBase):
    def __init__(self, conf=None):
        super(Driver, self).__init__()

        self.conf = conf
        if conf is None:
            self.conf = CONF
        kkb_conf.register_opts(self.conf)

        self.keycloak = KeycloakAdmin(
            connection=KeycloakOpenIDConnection(
                server_url=self.conf.keycloak.server_url,
                username=self.conf.keycloak.username,
                password=self.conf.keycloak.password,
                realm_name=self.conf.keycloak.realm_name,
                user_realm_name=self.conf.keycloak.user_realm_name,
                client_id=self.conf.keycloak.client_id,
                verify=self.conf.keycloak.verify,
            )
        )

    def is_domain_aware(self):
        # TODO(mnaser): check this
        return False

    def authenticate(self, user_id, password):
        user = self.keycloak.get_user(user_id)
        if user is None:
            raise exception.UserNotFound(user_id=user_id)
        if not user["enabled"]:
            raise exception.UserDisabled(user_id=user_id)

        # NOTE(mnaser): We don't want to authenticate here since we're only
        #               going to be used for federated authentication.
        raise AssertionError()

    def create_user(self, user_id, user):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_users(self, hints):
        # TODO(mnaser): Hints
        return [utils.keycloak_to_keystone_user(u) for u in self.keycloak.get_users()]

    def unset_default_project_id(self, project_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_users_in_group(self, group_id, hints):
        # TODO
        pass

    def get_user(self, user_id):
        return utils.keycloak_to_keystone_user(self.keycloak.get_user(user_id))

    def update_user(self, user_id, user):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def change_password(self, user_id, new_password):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def add_user_to_group(self, user_id, group_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def check_user_in_group(self, user_id, group_id):
        # TODO
        pass

    def remove_user_from_group(self, user_id, group_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def delete_user(self, user_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def get_user_by_name(self, user_name, domain_id):
        # TODO
        pass

    def create_group(self, group_id, group):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_groups(self, hints):
        # TODO
        pass

    def list_groups_for_user(self, user_id, hints):
        # TODO
        pass

    def get_group(self, group_id):
        # TODO
        pass

    def get_group_by_name(self, group_name, domain_id):
        # TODO
        pass

    def update_group(self, group_id, group):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def delete_group(self, group_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)
