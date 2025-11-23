# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

import logging
import uuid

from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak import exceptions as keycloak_exceptions
from keystone import exception
from keystone.identity.backends import base

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

    def _get_fresh_token(self):
        """Get a fresh access token using Service Account or Direct Grant authentication."""
        # Use user_realm_name for Direct Grant (where user exists) or fall back to realm_name
        auth_realm = (
            getattr(self.conf.keycloak, "user_realm_name", None)
            or self.conf.keycloak.realm_name
        )

        openid_client = KeycloakOpenID(
            server_url=self.conf.keycloak.server_url,
            realm_name=auth_realm,
            client_id=self.conf.keycloak.client_id,
            client_secret_key=getattr(self.conf.keycloak, "client_secret_key", None),
            verify=self.conf.keycloak.verify,
        )

        try:
            if getattr(self.conf.keycloak, "client_secret_key", None):
                # Use Service Account authentication (OAuth 2.0 Client Credentials Grant)
                LOG.info(
                    "Using Service Account authentication with Client Credentials Grant"
                )
                LOG.info(f"Realm: {self.conf.keycloak.realm_name}")
                LOG.info(f"Client ID: {self.conf.keycloak.client_id}")
                token = openid_client.token(grant_type="client_credentials")
            else:
                # Fall back to Direct Grant authentication (username/password)
                username = getattr(self.conf.keycloak, "username", None)
                if not username:
                    raise Exception(
                        "Neither client_secret_key nor username is configured for authentication"
                    )
                LOG.info("Using Direct Grant authentication with username/password")
                LOG.info(f"Realm: {self.conf.keycloak.realm_name}")
                LOG.info(f"Client ID: {self.conf.keycloak.client_id}")
                LOG.info(f"User Realm: {self.conf.keycloak.user_realm_name}")
                LOG.info(f"Username: {username}")
                token = openid_client.token(
                    username=username,
                    password=self.conf.keycloak.password,
                    grant_type="password",
                )

            return token
        except Exception as e:
            LOG.error(f"Failed to get access token: {e}")
            raise exception.Unauthorized("Authentication failed")

    def _get_cache_keys(self):
        """Calculate config hash and return cache keys for KeycloakAdmin instance and token."""
        config_hash = hash(
            (
                self.conf.keycloak.server_url,
                self.conf.keycloak.realm_name,
                getattr(self.conf.keycloak, "user_realm_name", ""),
                self.conf.keycloak.client_id,
                getattr(self.conf.keycloak, "client_secret_key", ""),
                getattr(self.conf.keycloak, "username", ""),
                getattr(self.conf.keycloak, "password", ""),
            )
        )
        cache_key = f"_keycloak_{config_hash}"
        token_key = f"_token_{config_hash}"
        return config_hash, cache_key, token_key

    @property
    def keycloak(self):
        # Create a unique cache key based on the domain configuration
        # This ensures each domain gets its own KeycloakAdmin instance
        config_hash, cache_key, token_key = self._get_cache_keys()

        if not hasattr(self, cache_key):
            # Log configuration for debugging if debug mode is enabled
            if getattr(self.conf.keycloak, "debug", False):
                client_secret_configured = bool(
                    getattr(self.conf.keycloak, "client_secret_key", None)
                )
                username_configured = bool(
                    getattr(self.conf.keycloak, "username", None)
                )

                LOG.warning(
                    f"KEYCLOAK_DEBUG: Initializing Keycloak client for config hash: {config_hash}"
                )
                LOG.warning(f"KEYCLOAK_DEBUG: Driver instance ID: {id(self)}")
                LOG.warning(
                    f"KEYCLOAK_DEBUG: Cache key exists: {hasattr(self, cache_key)}"
                )
                LOG.warning(
                    f"KEYCLOAK_DEBUG: Client Secret configured: {client_secret_configured}"
                )
                LOG.warning(
                    f"KEYCLOAK_DEBUG: Username configured: {username_configured}"
                )
                LOG.warning(
                    f"KEYCLOAK_DEBUG: Server URL: {self.conf.keycloak.server_url}"
                )
                LOG.warning(f"KEYCLOAK_DEBUG: Realm: {self.conf.keycloak.realm_name}")
                LOG.warning(
                    f"KEYCLOAK_DEBUG: Target Realm: {self.conf.keycloak.realm_name}"
                )
                user_realm = (
                    getattr(self.conf.keycloak, "user_realm_name", None)
                    or self.conf.keycloak.realm_name
                )
                LOG.warning(f"KEYCLOAK_DEBUG: Auth Realm: {user_realm}")
                LOG.warning(
                    f"KEYCLOAK_DEBUG: Client ID: {self.conf.keycloak.client_id}"
                )

            # Get fresh token and create new KeycloakAdmin
            fresh_token = self._get_fresh_token()
            setattr(self, token_key, fresh_token)

            # Always use token-based authentication to avoid double auth
            # (both Service Account and Direct Grant provide valid tokens)
            # For Service Account: use full token (no refresh_token typically)
            # For Direct Grant: remove refresh_token to prevent invalid refresh token errors
            token_for_admin = fresh_token
            if not getattr(self.conf.keycloak, "client_secret_key", None):
                # Direct Grant - remove refresh_token to prevent refresh errors
                if isinstance(fresh_token, dict) and "refresh_token" in fresh_token:
                    token_for_admin = fresh_token.copy()
                    del token_for_admin["refresh_token"]
            keycloak_instance = KeycloakAdmin(
                server_url=self.conf.keycloak.server_url,
                realm_name=self.conf.keycloak.realm_name,
                verify=self.conf.keycloak.verify,
                token=token_for_admin,
            )

            setattr(self, cache_key, keycloak_instance)
        else:
            # Using cached instance - log this for debugging
            if getattr(self.conf.keycloak, "debug", False):
                LOG.warning(
                    f"KEYCLOAK_DEBUG: Using cached Keycloak client for config hash: {config_hash}"
                )
                LOG.warning(f"KEYCLOAK_DEBUG: Driver instance ID: {id(self)}")

        return getattr(self, cache_key)

    def _refresh_token_and_client(self):
        """Helper method to refresh token and recreate KeycloakAdmin client."""
        # Get cache keys
        _, cache_key, token_key = self._get_cache_keys()

        # Get fresh token
        fresh_token = self._get_fresh_token()
        setattr(self, token_key, fresh_token)

        # Always use token-based authentication to avoid double auth
        # (both Service Account and Direct Grant provide valid tokens)
        # For Service Account: use full token (no refresh_token typically)
        # For Direct Grant: remove refresh_token to prevent invalid refresh token errors
        token_for_admin = fresh_token
        if not getattr(self.conf.keycloak, "client_secret_key", None):
            # Direct Grant - remove refresh_token to prevent refresh errors
            if isinstance(fresh_token, dict) and "refresh_token" in fresh_token:
                token_for_admin = fresh_token.copy()
                del token_for_admin["refresh_token"]
        keycloak_instance = KeycloakAdmin(
            server_url=self.conf.keycloak.server_url,
            realm_name=self.conf.keycloak.realm_name,
            verify=self.conf.keycloak.verify,
            token=token_for_admin,
        )

        setattr(self, cache_key, keycloak_instance)

    def _generate_403_error_message(
        self, operation_name, auth_method, auth_id, original_error
    ):
        """Generate 403 error message based on debug flag."""
        if getattr(self.conf.keycloak, "debug", False):
            return (
                f"Keycloak admin permission denied (403) for operation '{operation_name}'. "
                f"Authentication method: {auth_method} using {auth_id} "
                f"in realm '{self.conf.keycloak.realm_name}' "
                f"lacks permission for Admin API endpoint "
                f"(likely /admin/realms/{self.conf.keycloak.realm_name}/users). "
                f"Ensure the {auth_method.lower()} has appropriate realm-management roles. "
                f"Full error: {original_error}"
            )
        else:
            return (
                f"Keycloak permission denied (403) for {auth_method.lower()} {auth_id} "
                f"in realm '{self.conf.keycloak.realm_name}'. "
                f"Check realm-management roles. Enable debug=true for details."
            )

    def _keycloak_with_retry(self, operation, *args, **kwargs):
        """Execute a Keycloak operation with automatic token refresh on 401 errors."""
        # Log the operation being called for debugging if debug mode is enabled
        if getattr(self.conf.keycloak, "debug", False):
            operation_name = getattr(operation, "__name__", str(operation))
            auth_method = self._auth_method
            auth_id = self._auth_identifier
            LOG.warning(f"KEYCLOAK_DEBUG: Calling {operation_name}")
            LOG.warning(f"KEYCLOAK_DEBUG: Auth Method: {auth_method} using {auth_id}")
            LOG.warning(f"KEYCLOAK_DEBUG: Server URL: {self.conf.keycloak.server_url}")
            LOG.warning(
                f"KEYCLOAK_DEBUG: User Realm: {getattr(self.conf.keycloak, 'user_realm_name', 'N/A')}"
            )
            LOG.warning(f"KEYCLOAK_DEBUG: Realm: {self.conf.keycloak.realm_name}")
            LOG.warning(f"KEYCLOAK_DEBUG: Client ID: {self.conf.keycloak.client_id}")

        try:
            result = operation(*args, **kwargs)
            if getattr(self.conf.keycloak, "debug", False):
                operation_name = getattr(operation, "__name__", str(operation))
                LOG.warning(f"KEYCLOAK_DEBUG: {operation_name} successful")
            return result
        except keycloak_exceptions.KeycloakAuthenticationError:
            # Token expired (401), get fresh token and recreate client
            if getattr(self.conf.keycloak, "debug", False):
                operation_name = getattr(operation, "__name__", str(operation))
                LOG.warning(
                    f"KEYCLOAK_DEBUG: Token expired during {operation_name}, refreshing..."
                )
            self._refresh_token_and_client()
            # Retry the operation with fresh token - get the method from the fresh instance
            operation_name = getattr(operation, "__name__", str(operation))
            fresh_operation = getattr(self.keycloak, operation_name)
            return fresh_operation(*args, **kwargs)
        except keycloak_exceptions.KeycloakGetError as e:
            # Get operation name for error logging
            operation_name = getattr(operation, "__name__", str(operation))

            # Log detailed error information only if debug mode is enabled
            if getattr(self.conf.keycloak, "debug", False):
                LOG.error(f"KEYCLOAK_ERROR: {operation_name} failed: {e}")
                LOG.error(
                    f"KEYCLOAK_ERROR: Response code: {getattr(e, 'response_code', 'unknown')}"
                )
                LOG.error(
                    f"KEYCLOAK_ERROR: Response body: {getattr(e, 'response_body', 'No response body')}"
                )
                endpoint_url = f"{self.conf.keycloak.server_url}/admin/realms/{self.conf.keycloak.realm_name}/users"
                LOG.error(f"KEYCLOAK_ERROR: Likely endpoint: {endpoint_url}")

            # Handle 403 Forbidden - could be stale permissions in cached token
            if e.response_code == 403:
                auth_method = self._auth_method
                auth_id = self._auth_identifier

                # Try refreshing token once in case permissions were recently changed
                if not hasattr(self, "_token_refresh_attempted"):
                    if getattr(self.conf.keycloak, "debug", False):
                        LOG.warning(
                            f"KEYCLOAK_DEBUG: Got 403 for {operation_name}, "
                            f"refreshing token in case permissions changed..."
                        )
                    self._token_refresh_attempted = True
                    self._refresh_token_and_client()
                    # Retry the operation with fresh token - get the method from the fresh instance
                    try:
                        operation_name = getattr(operation, "__name__", str(operation))
                        fresh_operation = getattr(self.keycloak, operation_name)
                        result = fresh_operation(*args, **kwargs)
                        # Reset the flag on successful retry
                        delattr(self, "_token_refresh_attempted")
                        return result
                    except keycloak_exceptions.KeycloakGetError as retry_e:
                        if retry_e.response_code == 403:
                            # Still 403 after refresh, it's a real permission issue
                            delattr(self, "_token_refresh_attempted")
                            raise Exception(
                                self._generate_403_error_message(
                                    operation_name, auth_method, auth_id, retry_e
                                )
                            )
                        else:
                            # Different error after retry, re-raise it
                            delattr(self, "_token_refresh_attempted")
                            raise
                else:
                    # Already attempted refresh, it's a real permission issue
                    delattr(self, "_token_refresh_attempted")
                    raise Exception(
                        self._generate_403_error_message(
                            operation_name, auth_method, auth_id, e
                        )
                    )
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
            users = self.keycloak.get_group_members(group_id)
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
        users = self.keycloak.get_users(
            query={"username": user_name, "max": 1, "exact": True}
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
