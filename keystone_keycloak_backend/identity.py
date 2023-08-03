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

from keystone import exception
from keystone.identity.backends import base

from keystone_keycloak_backend import config
from keystone_keycloak_backend._vendor.keycloak import (
    KeycloakAdmin,
    KeycloakOpenIDConnection,
)
from keystone_keycloak_backend._vendor.keycloak import exceptions as keycloak_exceptions

READ_ONLY_ERROR_MESSAGE = "Keycloak does not support write operations"


class Driver(base.IdentityDriverBase):
    def __init__(self, conf=None):
        super(Driver, self).__init__()

        self.conf = conf
        config.register_opts(self.conf)

    @property
    def keycloak(self):
        if not hasattr(self, "_keycloak"):
            self._keycloak = KeycloakAdmin(
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
        return self._keycloak

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

    def _format_user(self, user):
        return {
            "id": user["id"],
            "name": user["username"],
            # "password":
            # "password_expires_at":
            "enabled": user["enabled"],
            # "default_project_id":
        }

    def create_user(self, user_id, user):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_users(self, hints):
        # TODO(mnaser): Hints
        users = self.keycloak.get_users()
        return [self._format_user(u) for u in users]

    def unset_default_project_id(self, project_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_users_in_group(self, group_id, hints):
        # TODO: hints
        try:
            users = self.keycloak.get_group_members(group_id)
        except keycloak_exceptions.KeycloakGetError as e:
            if e.response_code == 404:
                raise exception.GroupNotFound(group_id=group_id)
            raise

        return [self._format_user(u) for u in users]

    def get_user(self, user_id):
        try:
            user = self.keycloak.get_user(user_id)
        except keycloak_exceptions.KeycloakGetError as e:
            if e.response_code == 404:
                raise exception.UserNotFound(user_id=user_id)
            raise

        return self._format_user(user)

    def update_user(self, user_id, user):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def change_password(self, user_id, new_password):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def add_user_to_group(self, user_id, group_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def check_user_in_group(self, user_id, group_id):
        user_groups = self.keycloak.get_user_groups(user_id)
        user_group_ids = [g["id"] for g in user_groups]

        if group_id not in user_group_ids:
            raise exception.NotFound()
        return True

    def remove_user_from_group(self, user_id, group_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def delete_user(self, user_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def get_user_by_name(self, user_name, domain_id):
        users = self.keycloak.get_users(
            query={"username": user_name, "max": 1, "exact": True}
        )
        if len(users) == 0 or users[0]["username"] != user_name:
            raise exception.UserNotFound(user_id=user_name)
        return self._format_user(users[0])

    def _format_group(self, group):
        return {
            "id": group["id"],
            "name": group["name"],
            "description": group["path"],
        }

    def _format_groups(self, groups):
        # NOTE(mnaser): This function exists because the Keycloak API returns
        #               subGroups so we have to do a bit of recursion to
        #               flatten the structure.
        formatted_groups = []
        for group in groups:
            formatted_groups.append(self._format_group(group))
            formatted_groups.extend(self._format_groups(group["subGroups"]))
        return formatted_groups

    def create_group(self, group_id, group):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_groups(self, hints):
        # TODO: hints
        groups = self.keycloak.get_groups()
        return self._format_groups(groups)

    def list_groups_for_user(self, user_id, hints):
        # TODO: hints
        groups = self.keycloak.get_user_groups(user_id)
        return self._format_groups(groups)

    def get_group(self, group_id):
        try:
            group = self.keycloak.get_group(group_id)
        except keycloak_exceptions.KeycloakGetError as e:
            if e.response_code == 404:
                raise exception.GroupNotFound(group_id=group_id)
            raise

        return self._format_group(group)

    def get_group_by_name(self, group_name, domain_id):
        groups = self.keycloak.get_groups(
            query={"name": group_name, "max": 1, "exact": True}
        )
        if len(groups) == 0 or groups[0]["name"] != group_name:
            raise exception.GroupNotFound(group_id=group_name)
        return self._format_group(groups[0])

    def update_group(self, group_id, group):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def delete_group(self, group_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)
