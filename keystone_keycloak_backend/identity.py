# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

import logging
import uuid

from keycloak import KeycloakAdmin
from keycloak import exceptions as keycloak_exceptions
from keystone import exception
from keystone.identity.backends import base
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt

from keystone_keycloak_backend import config

READ_ONLY_ERROR_MESSAGE = "Keycloak does not support write operations"

LOG = logging.getLogger(__name__)


class Driver(base.IdentityDriverBase):
    def __init__(self, conf=None):
        super(Driver, self).__init__()

        self.conf = conf
        config.register_opts(self.conf)

    @property
    def _auth_method(self):
        """Determine which authentication method is being used."""
        return (
            "Service Account"
            if getattr(self.conf.keycloak, "client_secret_key", None)
            else "Direct Grant"
        )

    @property
    def _auth_identifier(self):
        """Get identifier for current authentication method."""
        if getattr(self.conf.keycloak, "client_secret_key", None):
            return f"client '{self.conf.keycloak.client_id}'"
        else:
            return f"user '{getattr(self.conf.keycloak, 'username', 'unknown')}'"

    @property
    def keycloak(self):
        """Initialized KeycloakAdmin instance.
        Each Driver instance is tied to a specific domain configuration.
        """
        if not hasattr(self, "_keycloak"):
            client_secret_configured = bool(
                getattr(self.conf.keycloak, "client_secret_key", None)
            )
            username_configured = bool(getattr(self.conf.keycloak, "username", None))

            LOG.debug("Initializing Keycloak client")
            LOG.debug("Driver instance ID: %s", id(self))
            LOG.debug("Client Secret configured: %s", client_secret_configured)
            LOG.debug("Username configured: %s", username_configured)
            LOG.debug("Server URL: %s", self.conf.keycloak.server_url)
            LOG.debug("Realm: %s", self.conf.keycloak.realm_name)
            LOG.debug("Target Realm: %s", self.conf.keycloak.realm_name)
            user_realm = (
                getattr(self.conf.keycloak, "user_realm_name", None)
                or self.conf.keycloak.realm_name
            )
            LOG.debug("Auth Realm: %s", user_realm)
            LOG.debug("Client ID: %s", self.conf.keycloak.client_id)

            self._keycloak = self._create_keycloak_admin()
        else:
            LOG.debug("Using cached Keycloak client")
            LOG.debug("Driver instance ID: %s", id(self))

        return self._keycloak

    def _create_keycloak_admin(self):
        """Create a new KeycloakAdmin instance based on configuration.

        This method handles both Service Account and Direct Grant authentication
        by creating KeycloakAdmin instances directly to avoid token-based
        initialization issues in python-keycloak 3.x.
        """
        if getattr(self.conf.keycloak, "client_secret_key", None):
            # Service Account authentication
            return KeycloakAdmin(
                server_url=self.conf.keycloak.server_url,
                realm_name=self.conf.keycloak.realm_name,
                client_id=self.conf.keycloak.client_id,
                client_secret_key=self.conf.keycloak.client_secret_key,
                verify=self.conf.keycloak.verify,
            )
        else:
            # Direct Grant authentication
            username = getattr(self.conf.keycloak, "username", None)
            if not username:
                raise Exception(
                    "Neither client_secret_key nor username is configured for authentication"
                )
            user_realm = (
                getattr(self.conf.keycloak, "user_realm_name", None)
                or self.conf.keycloak.realm_name
            )
            return KeycloakAdmin(
                server_url=self.conf.keycloak.server_url,
                realm_name=self.conf.keycloak.realm_name,
                username=username,
                password=self.conf.keycloak.password,
                user_realm_name=user_realm,
                verify=self.conf.keycloak.verify,
            )

    def _refresh_token_and_client(self):
        """Refresh token and recreate KeycloakAdmin client."""
        self._keycloak = self._create_keycloak_admin()

    def _generate_403_error_message(
        self, operation_name, auth_method, auth_id, original_error
    ):
        """Generate 403 error message with detailed logging."""
        return (
            f"Keycloak permission denied (403) for operation {operation_name} using {auth_method.lower()} {auth_id} "
            f"in realm '{self.conf.keycloak.realm_name}'. "
            f"Admin API endpoint (likely /admin/realms/{self.conf.keycloak.realm_name}/users) requires "
            f"realm-management roles. Full error: {original_error}"
        )

    def _keycloak_call_with_auth_retry(self, operation, *args, **kwargs):
        """Execute Keycloak operation with automatic retry on authentication errors."""
        for attempt in Retrying(
            retry=retry_if_exception_type(
                keycloak_exceptions.KeycloakAuthenticationError
            ),
            stop=stop_after_attempt(2),
        ):
            with attempt:
                if attempt.retry_state.attempt_number > 1:
                    self._refresh_token_and_client()
                    operation_name = getattr(operation, "__name__", str(operation))
                    operation = getattr(self.keycloak, operation_name)
                return operation(*args, **kwargs)

    def _keycloak_with_retry(self, operation, *args, **kwargs):
        """Execute a Keycloak operation with retry logic."""
        operation_name = getattr(operation, "__name__", str(operation))
        auth_method = self._auth_method
        auth_id = self._auth_identifier
        LOG.debug("Calling %s", operation_name)
        LOG.debug("Auth Method: %s using %s", auth_method, auth_id)
        LOG.debug("Server URL: %s", self.conf.keycloak.server_url)
        LOG.debug(
            "User Realm: %s", getattr(self.conf.keycloak, "user_realm_name", "N/A")
        )
        LOG.debug("Realm: %s", self.conf.keycloak.realm_name)
        LOG.debug("Client ID: %s", self.conf.keycloak.client_id)

        try:
            result = self._keycloak_call_with_auth_retry(operation, *args, **kwargs)
            LOG.debug("%s successful", operation_name)
            return result
        except keycloak_exceptions.KeycloakGetError as e:
            LOG.debug("%s failed: %s", operation_name, e)
            LOG.debug("Response code: %s", getattr(e, "response_code", "unknown"))
            LOG.debug(
                "Response body: %s", getattr(e, "response_body", "No response body")
            )
            endpoint_url = f"{self.conf.keycloak.server_url}/admin/realms/{self.conf.keycloak.realm_name}/users"
            LOG.debug("Likely endpoint: %s", endpoint_url)

            # Handle 403 Forbidden - try one refresh in case permissions changed
            if e.response_code == 403:
                LOG.debug(
                    "Got 403 for %s, trying token refresh in case permissions changed...",
                    operation_name,
                )
                try:
                    self._refresh_token_and_client()
                    # Retry with fresh token
                    fresh_operation = getattr(self.keycloak, operation_name)
                    result = self._keycloak_call_with_auth_retry(
                        fresh_operation, *args, **kwargs
                    )
                    LOG.debug("%s successful after token refresh", operation_name)
                    return result
                except keycloak_exceptions.KeycloakGetError as retry_e:
                    if retry_e.response_code == 403:
                        # Still 403 after refresh, it's a real permission issue
                        raise Exception(
                            self._generate_403_error_message(
                                operation_name, auth_method, auth_id, retry_e
                            )
                        )
                    else:
                        # Different error after retry, re-raise it
                        raise
            # Re-raise other KeycloakGetError exceptions as-is
            raise

    def is_domain_aware(self):
        # TODO(mnaser): check this
        return False

    def authenticate(self, user_id, password):
        user_id = uuid.UUID(user_id)
        user = self._keycloak_with_retry(self.keycloak.get_user, user_id)
        if user is None:
            raise exception.UserNotFound(user_id=user_id)
        if not user["enabled"]:
            raise exception.UserDisabled(user_id=user_id)

        # NOTE(mnaser): We don't want to authenticate here since we're only
        #               going to be used for federated authentication.
        raise AssertionError()

    def _format_user(self, user):
        user_id = uuid.UUID(user["id"])

        formatted_user = {
            "id": user_id.hex,
            "name": user["username"],
            # "password":
            # TODO(mnaser): We should probably find a way to scrape into the
            #               credentials API and return the expiry date.
            "password_expires_at": None,
            "enabled": user["enabled"],
            # "default_project_id":
            # NOTE(mnaser): This is required or we'll fail with a KeyError
            #               https://bugs.launchpad.net/keystone/+bug/1662762
            "options": {},
        }

        # Combine Keycloak firstName and lastName into Keystone's
        # `description` field. Keystone's user schema for this backend
        # doesn't expose first_name/last_name fields directly, so we
        # put a combined display name into `description`.
        #
        # Handle edge cases: None, empty strings, whitespace-only values
        # should be ignored. If both parts are missing/empty, don't set
        # the description key.
        first = user.get("firstName")
        last = user.get("lastName")

        name_parts = []
        if first and str(first).strip():
            name_parts.append(str(first).strip())
        if last and str(last).strip():
            name_parts.append(str(last).strip())

        if name_parts:
            # Join with single space, e.g. "Name Surname", "Name", or "Surname"
            formatted_user["description"] = " ".join(name_parts)

        # Add email if available from Keycloak user object
        if user.get("email"):
            formatted_user["email"] = user["email"]

        return formatted_user

    def create_user(self, user_id, user):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_users(self, hints):
        # TODO(mnaser): Hints
        users = self._keycloak_with_retry(self.keycloak.get_users)
        return [self._format_user(u) for u in users]

    def unset_default_project_id(self, project_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_users_in_group(self, group_id, hints):
        # TODO: hints
        group_id = uuid.UUID(group_id)

        try:
            users = self._keycloak_with_retry(self.keycloak.get_group_members, group_id)
        except keycloak_exceptions.KeycloakGetError as e:
            if e.response_code == 404:
                raise exception.GroupNotFound(group_id=group_id)
            raise

        return [self._format_user(u) for u in users]

    def get_user(self, user_id):
        user_id = uuid.UUID(user_id)

        try:
            user = self._keycloak_with_retry(self.keycloak.get_user, user_id)
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
        user_id = uuid.UUID(user_id)
        group_id = uuid.UUID(group_id)

        user_groups = self._keycloak_with_retry(self.keycloak.get_user_groups, user_id)
        user_group_ids = [g["id"] for g in user_groups]

        if str(group_id) not in user_group_ids:
            raise exception.NotFound()
        return True

    def remove_user_from_group(self, user_id, group_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def delete_user(self, user_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def reset_last_active(self):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def get_user_by_name(self, user_name, domain_id):
        users = self._keycloak_with_retry(
            self.keycloak.get_users,
            query={"username": user_name, "max": 1, "exact": True},
        )
        if len(users) == 0 or users[0]["username"] != user_name:
            raise exception.UserNotFound(user_id=user_name)
        return self._format_user(users[0])

    def _format_group(self, group):
        group_id = uuid.UUID(group["id"])

        return {
            "id": group_id.hex,
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
            if "subGroups" in group:
                formatted_groups.extend(self._format_groups(group["subGroups"]))
        return formatted_groups

    def create_group(self, group_id, group):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def list_groups(self, hints):
        # TODO: hints
        groups = self._keycloak_with_retry(self.keycloak.get_groups)
        return self._format_groups(groups)

    def list_groups_for_user(self, user_id, hints):
        # TODO: hints
        user_id = uuid.UUID(user_id)
        groups = self._keycloak_with_retry(self.keycloak.get_user_groups, user_id)
        return self._format_groups(groups)

    def get_group(self, group_id):
        group_id = uuid.UUID(group_id)

        try:
            group = self._keycloak_with_retry(self.keycloak.get_group, group_id)
        except keycloak_exceptions.KeycloakGetError as e:
            if e.response_code == 404:
                raise exception.GroupNotFound(group_id=group_id)
            raise

        return self._format_group(group)

    def get_group_by_name(self, group_name, domain_id):
        groups = self._keycloak_with_retry(
            self.keycloak.get_groups,
            query={"name": group_name, "max": 1, "exact": True},
        )
        if len(groups) == 0 or groups[0]["name"] != group_name:
            raise exception.GroupNotFound(group_id=group_name)
        return self._format_group(groups[0])

    def update_group(self, group_id, group):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)

    def delete_group(self, group_id):
        raise exception.Forbidden(READ_ONLY_ERROR_MESSAGE)
