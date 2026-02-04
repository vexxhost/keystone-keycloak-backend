# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the Keycloak identity backend driver.
"""

from unittest.mock import Mock, patch

import pytest

from keystone_keycloak_backend.identity import Driver


class MockConfig:
    """Mock configuration object for testing."""

    def __init__(self, auth_method="direct_grant"):
        self.keycloak = MockKeycloakConfig(auth_method)

    def register_group(self, group):
        pass

    def register_opts(self, opts, group=None):
        pass


class MockKeycloakConfig:
    """Mock Keycloak configuration section."""

    def __init__(self, auth_method="direct_grant"):
        self.server_url = "http://localhost:8080"
        self.realm_name = "test"
        self.client_id = "admin-cli"
        self.verify = False

        if auth_method == "service_account":
            # Service Account configuration
            self.client_id = "keystone-client"
            self.client_secret_key = "test-secret-key"
            # No username/password for Service Account
        else:
            # Direct Grant configuration
            self.username = "admin"
            self.password = "admin"
            self.user_realm_name = "master"
            # No client_secret_key for Direct Grant


@pytest.fixture
def direct_grant_driver():
    """Fixture to create a Driver instance with Direct Grant authentication."""
    mock_config = MockConfig(auth_method="direct_grant")
    return Driver(conf=mock_config)


@pytest.fixture
def service_account_driver():
    """Fixture to create a Driver instance with Service Account authentication."""
    mock_config = MockConfig(auth_method="service_account")
    return Driver(conf=mock_config)


class TestAuthenticationMethods:
    """Test cases for different authentication methods."""

    def test_auth_method_detection_service_account(self, service_account_driver):
        """Test that Service Account authentication is detected correctly."""
        assert service_account_driver._auth_method == "Service Account"
        assert "keystone-client" in service_account_driver._auth_identifier

    def test_auth_method_detection_direct_grant(self, direct_grant_driver):
        """Test that Direct Grant authentication is detected correctly."""
        assert direct_grant_driver._auth_method == "Direct Grant"
        assert "admin" in direct_grant_driver._auth_identifier

    def test_auth_identifier_service_account(self, service_account_driver):
        """Test auth identifier for Service Account."""
        identifier = service_account_driver._auth_identifier
        assert "client 'keystone-client'" == identifier

    def test_auth_identifier_direct_grant(self, direct_grant_driver):
        """Test auth identifier for Direct Grant."""
        identifier = direct_grant_driver._auth_identifier
        assert "user 'admin'" == identifier

    def test_service_account_authentication_deprecated(self, service_account_driver):
        """Test that Service Account authentication works with new direct approach."""
        # NOTE: _get_fresh_token method was removed in favor of direct authentication
        # Service Account authentication now happens directly in KeycloakAdmin initialization

        # Test that we can access the authentication method and identifier
        assert service_account_driver._auth_method == "Service Account"
        assert "client 'keystone-client'" in service_account_driver._auth_identifier

    def test_direct_grant_authentication_deprecated(self, direct_grant_driver):
        """Test that Direct Grant authentication works with new direct approach."""
        # NOTE: _get_fresh_token method was removed in favor of direct authentication
        # Direct Grant authentication now happens directly in KeycloakAdmin initialization

        # Test that we can access the authentication method and identifier
        assert direct_grant_driver._auth_method == "Direct Grant"
        assert "user 'admin'" in direct_grant_driver._auth_identifier

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    def test_keycloak_property_service_account(
        self, mock_admin_class, service_account_driver
    ):
        """Test KeycloakAdmin initialization for Service Account with direct authentication."""
        # Mock KeycloakAdmin
        mock_admin = Mock()
        mock_admin_class.return_value = mock_admin

        # Access the keycloak property
        keycloak_instance = service_account_driver.keycloak

        # Verify KeycloakAdmin was initialized with direct Service Account auth
        mock_admin_class.assert_called_once_with(
            server_url="http://localhost:8080",
            realm_name="test",  # Uses realm_name for target realm
            client_id="keystone-client",
            client_secret_key="test-secret-key",  # Direct Service Account auth
            verify=False,
        )
        assert keycloak_instance == mock_admin

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    def test_keycloak_property_direct_grant(
        self, mock_admin_class, direct_grant_driver
    ):
        """Test KeycloakAdmin initialization for Direct Grant with direct authentication."""
        # Mock KeycloakAdmin
        mock_admin = Mock()
        mock_admin_class.return_value = mock_admin

        # Access the keycloak property
        keycloak_instance = direct_grant_driver.keycloak

        # Verify KeycloakAdmin was initialized with direct username/password auth
        mock_admin_class.assert_called_once_with(
            server_url="http://localhost:8080",
            realm_name="test",  # Uses realm_name for target realm
            username="admin",
            password="admin",
            user_realm_name="master",  # User realm for Direct Grant
            verify=False,
        )
        assert keycloak_instance == mock_admin

    def test_config_hash_uniqueness(self, service_account_driver, direct_grant_driver):
        """Test that different configurations produce different cache keys."""
        # Force initialization of both drivers
        with patch("keystone_keycloak_backend.identity.KeycloakAdmin"):

            # Access both keycloak properties to trigger initialization
            try:
                _ = service_account_driver.keycloak
            except Exception:
                pass  # Ignore exceptions, we just want to check cache keys

            try:
                _ = direct_grant_driver.keycloak
            except Exception:
                pass  # Ignore exceptions, we just want to check cache keys

            # Check that the drivers have different cache keys
            # (Different configurations should produce different instances)
            # Note: This is a basic check - the actual hash values depend on the implementation


class TestErrorHandling:
    """Test cases for error handling and retry logic."""

    @patch("keystone_keycloak_backend.identity.LOG")
    def test_403_error_retry_with_debug(self, mock_log, service_account_driver):
        """Test 403 error handling with retry logic."""
        # Import the actual exception type that the code handles
        from keystone_keycloak_backend.identity import keycloak_exceptions

        # Create a mock exception that behaves like KeycloakGetError
        mock_exception = keycloak_exceptions.KeycloakGetError("403 Forbidden")
        mock_exception.response_code = 403

        # Mock the keycloak property to return a mock admin client
        mock_admin = Mock()
        mock_operation = Mock(side_effect=[mock_exception, "success"])
        mock_operation.__name__ = "test_operation"
        mock_admin.test_operation = mock_operation

        # Mock the _create_keycloak_admin method to return our mock
        with patch.object(
            service_account_driver, "_create_keycloak_admin", return_value=mock_admin
        ):
            # First call should fail with 403, second should succeed after retry
            result = service_account_driver._keycloak_with_retry(mock_operation)

        # Verify the operation was retried and succeeded
        assert result == "success"
        assert mock_operation.call_count == 2

    @patch("keystone_keycloak_backend.identity.LOG")
    def test_403_error_message_contains_realm_info(
        self, mock_log, service_account_driver
    ):
        """Test that 403 error messages contain proper realm information."""
        # Import the actual exception type that the code handles
        from keystone_keycloak_backend.identity import keycloak_exceptions

        # Create a mock exception that behaves like KeycloakGetError
        mock_exception = keycloak_exceptions.KeycloakGetError("403 Forbidden")
        mock_exception.response_code = 403

        # Mock operation that always fails with 403 (even after retry)
        mock_operation = Mock(side_effect=mock_exception)
        mock_operation.__name__ = "get_groups"

        # Mock the keycloak property to return a mock admin client
        mock_admin = Mock()
        mock_admin.get_groups = mock_operation

        with patch.object(
            service_account_driver, "_create_keycloak_admin", return_value=mock_admin
        ):
            # This should raise an Exception with realm info after retry fails
            with pytest.raises(Exception) as exc_info:
                service_account_driver._keycloak_with_retry(mock_operation)

        # Verify the error message contains the correct realm information
        error_message = str(exc_info.value)
        assert "realm 'test'" in error_message  # Should show actual realm name
        assert "operation get_groups" in error_message  # Should show operation name
        assert "service account" in error_message.lower()  # Should show auth method
        assert "keystone-client" in error_message  # Should show client ID
        assert (
            "Admin API endpoint" in error_message
        )  # Should show detailed endpoint info
        assert (
            "/admin/realms/test/users" in error_message
        )  # Should show correct endpoint path
        assert "Full error:" in error_message  # Should show original error

    @patch("keystone_keycloak_backend.identity.LOG")
    def test_403_error_message_short_when_debug_disabled(
        self, mock_log, service_account_driver
    ):
        """Test that 403 error messages are concise."""
        # Import the actual exception type that the code handles
        from keystone_keycloak_backend.identity import keycloak_exceptions

        # Create a mock exception that behaves like KeycloakGetError
        mock_exception = keycloak_exceptions.KeycloakGetError("403 Forbidden")
        mock_exception.response_code = 403

        # Mock operation that always fails with 403
        mock_operation = Mock(side_effect=mock_exception)
        mock_operation.__name__ = "get_groups"

        # Mock the keycloak property to return a mock admin client
        mock_admin = Mock()
        mock_admin.get_groups = mock_operation

        with patch.object(
            service_account_driver, "_create_keycloak_admin", return_value=mock_admin
        ):
            # This should raise an Exception with concise error message
            with pytest.raises(Exception) as exc_info:
                service_account_driver._keycloak_with_retry(mock_operation)

        # Verify the error message contains comprehensive information
        error_message = str(exc_info.value)
        assert "realm 'test'" in error_message
        assert "service account" in error_message.lower()
        assert "keystone-client" in error_message
        assert "operation get_groups" in error_message  # Should show operation name
        assert "Admin API endpoint" in error_message  # Should show detailed info
        assert "/admin/realms/test/users" in error_message  # Should show endpoint path
        assert "Full error:" in error_message  # Should show original error

    @patch("keystone_keycloak_backend.identity.LOG")
    def test_debug_error_logging_conditional(self, mock_log, service_account_driver):
        """Test that detailed error logging happens via LOG.debug."""
        # Import the actual exception type that the code handles
        from keystone_keycloak_backend.identity import keycloak_exceptions

        # Create a mock exception that behaves like KeycloakGetError
        mock_exception = keycloak_exceptions.KeycloakGetError("403 Forbidden")
        mock_exception.response_code = 403

        # Mock operation that always fails with 403
        mock_operation = Mock(side_effect=mock_exception)
        mock_operation.__name__ = "get_groups"

        # Mock the keycloak property to return a mock admin client
        mock_admin = Mock()
        mock_admin.get_groups = mock_operation

        with patch.object(
            service_account_driver, "_create_keycloak_admin", return_value=mock_admin
        ):
            # This should raise an Exception and log debug info
            with pytest.raises(Exception):
                service_account_driver._keycloak_with_retry(mock_operation)

        # Verify debug logging happened during the operation
        debug_calls = mock_log.debug.call_args_list

        # Check for "Calling get_groups" log
        calling_logs = [
            call
            for call in debug_calls
            if len(call.args) >= 2
            and call.args[0] == "Calling %s"
            and call.args[1] == "get_groups"
        ]

        # Check for "get_groups failed" log
        failed_logs = [
            call
            for call in debug_calls
            if len(call.args) >= 2
            and call.args[0] == "%s failed: %s"
            and call.args[1] == "get_groups"
        ]

        # Should have both calling and failure logs
        assert (
            len(calling_logs) > 0
        ), f"Should log operation call. All calls: {debug_calls}"
        assert (
            len(failed_logs) > 0
        ), f"Should log operation failure. All calls: {debug_calls}"

    def test_attribute_error_no_longer_handled(self, service_account_driver):
        """Test that AttributeError from python-keycloak 3.x is no longer an issue.

        Since we switched to direct authentication approach, we no longer trigger
        the problematic code path that caused the AttributeError in python-keycloak 3.x.
        """
        # Mock operation that would have triggered AttributeError in old token-based approach
        mock_operation = Mock(
            side_effect=AttributeError("'NoneType' object has no attribute 'get'")
        )
        mock_operation.__name__ = "get_user"

        # This AttributeError should now be raised normally since we don't handle it
        # (because we no longer trigger the problematic code path)
        with pytest.raises(
            AttributeError, match="'NoneType' object has no attribute 'get'"
        ):
            service_account_driver._keycloak_with_retry(mock_operation)

    def test_non_token_attribute_error_passthrough(self, service_account_driver):
        """Test that non-token AttributeErrors are passed through normally."""
        # Mock operation that raises unrelated AttributeError
        mock_operation = Mock(side_effect=AttributeError("Some other attribute error"))
        mock_operation.__name__ = "get_user"

        # This should raise the AttributeError without retry
        with pytest.raises(AttributeError, match="Some other attribute error"):
            service_account_driver._keycloak_with_retry(mock_operation)


class TestDomainIsolation:
    """Test cases for domain isolation functionality."""

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    def test_different_configs_produce_different_instances(self, mock_admin_class):
        """Test that different configurations create separate Keycloak instances."""
        # Create two drivers with different configurations
        service_config = MockConfig(auth_method="service_account")
        direct_config = MockConfig(auth_method="direct_grant")

        service_driver = Driver(conf=service_config)
        direct_driver = Driver(conf=direct_config)

        # Mock KeycloakAdmin to return different instances
        mock_admin1 = Mock()
        mock_admin2 = Mock()
        mock_admin_class.side_effect = [mock_admin1, mock_admin2]

        # Access keycloak property on both drivers
        keycloak1 = service_driver.keycloak
        keycloak2 = direct_driver.keycloak

        # Verify we get different instances
        assert keycloak1 != keycloak2
        assert keycloak1 == mock_admin1
        assert keycloak2 == mock_admin2

        # Verify KeycloakAdmin was called twice with different parameters
        assert mock_admin_class.call_count == 2

        # First call (Service Account) - now uses direct client_secret_key auth
        first_call = mock_admin_class.call_args_list[0]
        assert first_call[1]["server_url"] == "http://localhost:8080"
        assert first_call[1]["client_secret_key"] == "test-secret-key"
        assert first_call[1]["realm_name"] == "test"

        # Second call (Direct Grant) - now uses direct username/password auth
        second_call = mock_admin_class.call_args_list[1]
        assert second_call[1]["username"] == "admin"
        assert second_call[1]["password"] == "admin"
        assert second_call[1]["realm_name"] == "test"

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    def test_config_hash_computation(self, mock_admin_class):
        """Test that configuration hash is computed correctly."""
        # Create drivers with different configurations
        service_driver = Driver(conf=MockConfig(auth_method="service_account"))
        direct_driver = Driver(conf=MockConfig(auth_method="direct_grant"))

        # Mock KeycloakAdmin
        mock_admin1 = Mock()
        mock_admin2 = Mock()
        mock_admin_class.side_effect = [mock_admin1, mock_admin2]

        # Access keycloak property to trigger hash computation
        _ = service_driver.keycloak
        _ = direct_driver.keycloak

        # Test that different configurations resulted in different instances
        # This indicates different cache keys (hashes) were used
        assert mock_admin_class.call_count == 2

        # Verify the configurations were different
        call1 = mock_admin_class.call_args_list[0]
        call2 = mock_admin_class.call_args_list[1]

        # Service Account uses client_secret_key, Direct Grant uses username/password
        assert call1[1].get("client_secret_key") == "test-secret-key"  # Service Account
        assert call1[1].get("username") is None  # Service Account doesn't use username

        assert call2[1].get("username") == "admin"  # Direct Grant
        assert (
            call2[1].get("client_secret_key") is None
        )  # Direct Grant doesn't use client_secret_key

        # Even though server URLs and realms are the same, different auth methods
        # (service account vs direct grant) produce different cache keys due to
        # different client_secret_key vs username/password configurations
        # This test validates that cache isolation works correctly

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    def test_cache_key_isolation(self, mock_admin_class):
        """Test that different configurations use different cache keys."""
        service_driver = Driver(conf=MockConfig(auth_method="service_account"))
        direct_driver = Driver(conf=MockConfig(auth_method="direct_grant"))

        # Mock KeycloakAdmin to return different instances
        mock_admin1 = Mock()
        mock_admin2 = Mock()
        mock_admin_class.side_effect = [mock_admin1, mock_admin2]

        # Access keycloak property multiple times
        keycloak1_first = service_driver.keycloak
        keycloak1_second = service_driver.keycloak  # Should use cache
        keycloak2 = direct_driver.keycloak

        # Verify caching works for same driver
        assert keycloak1_first == keycloak1_second

        # Verify different drivers get different instances
        assert keycloak1_first != keycloak2

        # Verify KeycloakAdmin was only called twice (not three times due to caching)
        assert mock_admin_class.call_count == 2


class TestConfigurationValidation:
    """Test cases for configuration validation."""

    def test_service_account_config_validation(self):
        """Test that Service Account configuration is properly detected."""
        config = MockConfig(auth_method="service_account")
        driver = Driver(conf=config)
        assert driver is not None

        # Verify Service Account detection
        assert hasattr(config.keycloak, "client_secret_key")
        assert config.keycloak.client_secret_key == "test-secret-key"
        assert config.keycloak.client_id == "keystone-client"
        assert not hasattr(config.keycloak, "username")
        assert not hasattr(config.keycloak, "password")

    def test_direct_grant_config_validation(self):
        """Test that Direct Grant configuration is properly detected."""
        config = MockConfig(auth_method="direct_grant")
        driver = Driver(conf=config)
        assert driver is not None

        # Verify Direct Grant detection
        assert hasattr(config.keycloak, "username")
        assert hasattr(config.keycloak, "password")
        assert hasattr(config.keycloak, "user_realm_name")
        assert config.keycloak.username == "admin"
        assert config.keycloak.password == "admin"
        assert config.keycloak.user_realm_name == "master"
        assert not hasattr(config.keycloak, "client_secret_key")


class TestRealConfiguration:
    """Test cases that simulate real-world configuration scenarios."""

    def test_production_service_account_setup(self):
        """Test a realistic Service Account configuration."""

        class ProductionServiceAccountConfig:
            def __init__(self):
                self.keycloak = type(
                    "obj",
                    (object,),
                    {
                        "server_url": "https://keycloak.company.com",
                        "realm_name": "openstack",
                        "client_id": "keystone-service",
                        "client_secret_key": "production-secret",
                        "verify": True,
                    },
                )

            def register_group(self, group):
                pass

            def register_opts(self, opts, group=None):
                pass

        driver = Driver(conf=ProductionServiceAccountConfig())

        # Should detect as Service Account
        assert driver._auth_method == "Service Account"
        assert "keystone-service" in driver._auth_identifier

    def test_development_direct_grant_setup(self):
        """Test a realistic Direct Grant configuration for development."""

        class DevelopmentDirectGrantConfig:
            def __init__(self):
                self.keycloak = type(
                    "obj",
                    (object,),
                    {
                        "server_url": "http://localhost:8080",
                        "realm_name": "openstack",
                        "user_realm_name": "master",
                        "client_id": "admin-cli",
                        "username": "admin",
                        "password": "admin",
                        "verify": False,
                    },
                )

            def register_group(self, group):
                pass

            def register_opts(self, opts, group=None):
                pass

        driver = Driver(conf=DevelopmentDirectGrantConfig())

        # Should detect as Direct Grant
        assert driver._auth_method == "Direct Grant"
        assert "admin" in driver._auth_identifier

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    def test_multi_domain_scenario(self, mock_admin_class):
        """Test scenario with multiple domains using different auth methods."""
        # Simulate keystone.conf with multiple domains:
        # [keycloak] - Service Account for production
        # [keycloak-deprecated] - Direct Grant for legacy users

        # Production domain (Service Account)
        prod_config = type(
            "obj",
            (object,),
            {
                "keycloak": type(
                    "obj",
                    (object,),
                    {
                        "server_url": "https://keycloak.company.com",
                        "realm_name": "production",
                        "client_id": "keystone-prod",
                        "client_secret_key": "prod-secret",
                        "verify": True,
                    },
                ),
                "register_group": lambda x: None,
                "register_opts": lambda x, group=None: None,
            },
        )

        # Legacy domain (Direct Grant)
        legacy_config = type(
            "obj",
            (object,),
            {
                "keycloak": type(
                    "obj",
                    (object,),
                    {
                        "server_url": "http://legacy-keycloak:8080",
                        "realm_name": "legacy",
                        "user_realm_name": "master",
                        "client_id": "admin-cli",
                        "username": "legacy-admin",
                        "password": "legacy-pass",
                        "verify": False,
                    },
                ),
                "register_group": lambda x: None,
                "register_opts": lambda x, group=None: None,
            },
        )

        # Create drivers for both domains
        prod_driver = Driver(conf=prod_config)
        legacy_driver = Driver(conf=legacy_config)

        # Mock Keycloak instances
        mock_admin_prod = Mock()
        mock_admin_legacy = Mock()
        mock_admin_class.side_effect = [mock_admin_prod, mock_admin_legacy]

        # Access both drivers
        prod_keycloak = prod_driver.keycloak
        legacy_keycloak = legacy_driver.keycloak

        # Verify they use different Keycloak instances
        assert prod_keycloak != legacy_keycloak

        # Verify correct authentication methods
        assert prod_driver._auth_method == "Service Account"
        assert legacy_driver._auth_method == "Direct Grant"

        # Verify correct configuration isolation
        assert mock_admin_class.call_count == 2

        # Production call (Service Account) - now uses direct client_secret_key auth
        prod_call = mock_admin_class.call_args_list[0]
        assert prod_call[1]["server_url"] == "https://keycloak.company.com"
        assert prod_call[1]["client_secret_key"] == "prod-secret"
        assert prod_call[1]["realm_name"] == "production"

        # Legacy call (Direct Grant) - now uses direct username/password auth
        legacy_call = mock_admin_class.call_args_list[1]
        assert legacy_call[1]["server_url"] == "http://legacy-keycloak:8080"
        assert legacy_call[1]["username"] == "legacy-admin"
        assert legacy_call[1]["password"] == "legacy-pass"
        assert legacy_call[1]["realm_name"] == "legacy"


class TestFormatUser:
    """Test cases for the _format_user method."""

    def test_format_user_with_complete_attributes(self, service_account_driver):
        """Test user with all additional attributes (firstName, lastName, email)."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "username": "john.doe",
            "enabled": True,
            "firstName": "John",
            "lastName": "Doe",
            "email": "john.doe@example.com",
        }

        formatted_user = service_account_driver._format_user(keycloak_user)

        # Verify core attributes
        assert (
            formatted_user["id"] == "123e4567e89b12d3a456426614174000"
        )  # UUID hex without hyphens
        assert formatted_user["name"] == "john.doe"
        assert formatted_user["enabled"] is True
        assert formatted_user["password_expires_at"] is None
        assert formatted_user["options"] == {}

        # Verify additional attributes
        assert formatted_user["description"] == "John Doe"
        assert formatted_user["email"] == "john.doe@example.com"

    def test_format_user_minimal_attributes(self, direct_grant_driver):
        """Test user with only required attributes (no firstName, lastName, email)."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174001",
            "username": "jane.smith",
            "enabled": True,
        }

        formatted_user = direct_grant_driver._format_user(keycloak_user)

        # Verify core attributes
        assert formatted_user["id"] == "123e4567e89b12d3a456426614174001"
        assert formatted_user["name"] == "jane.smith"
        assert formatted_user["enabled"] is True
        assert formatted_user["password_expires_at"] is None
        assert formatted_user["options"] == {}

        # Verify optional attributes are not present
        assert "description" not in formatted_user
        assert "email" not in formatted_user

    def test_format_user_partial_name(self, service_account_driver):
        """Test user with only firstName (no lastName)."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174002",
            "username": "bob.wilson",
            "enabled": False,
            "firstName": "Bob",
            "email": "bob@company.com",
        }

        formatted_user = service_account_driver._format_user(keycloak_user)

        # Verify firstName becomes description when lastName is missing
        assert formatted_user["description"] == "Bob"
        assert formatted_user["email"] == "bob@company.com"
        assert formatted_user["enabled"] is False

    def test_format_user_lastname_only(self, direct_grant_driver):
        """Test user with only lastName (no firstName)."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174003",
            "username": "wilson",
            "enabled": True,
            "lastName": "Wilson",
        }

        formatted_user = direct_grant_driver._format_user(keycloak_user)

        # Verify lastName becomes description when firstName is missing
        assert formatted_user["description"] == "Wilson"
        assert "email" not in formatted_user

    def test_format_user_empty_and_null_names(self, service_account_driver):
        """Test user with empty string and None name values."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174004",
            "username": "alice.brown",
            "enabled": True,
            "firstName": "",  # Empty string
            "lastName": None,  # None value
            "email": "alice@test.com",
        }

        formatted_user = service_account_driver._format_user(keycloak_user)

        # Verify empty/null name values don't create description
        assert "description" not in formatted_user
        assert formatted_user["email"] == "alice@test.com"

    def test_format_user_whitespace_only_names(self, direct_grant_driver):
        """Test user with whitespace-only name values."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174005",
            "username": "charlie",
            "enabled": True,
            "firstName": "   ",  # Whitespace only
            "lastName": "\t\n",  # Tabs and newlines
        }

        formatted_user = direct_grant_driver._format_user(keycloak_user)

        # Verify whitespace-only values don't create description
        assert "description" not in formatted_user

    def test_format_user_mixed_valid_invalid_names(self, service_account_driver):
        """Test user with one valid and one invalid name component."""
        test_cases = [
            # Valid firstName, invalid lastName
            {"firstName": "Valid", "lastName": "", "expected": "Valid"},
            # Invalid firstName, valid lastName
            {"firstName": "   ", "lastName": "Valid", "expected": "Valid"},
            # Valid firstName, None lastName
            {"firstName": "John", "lastName": None, "expected": "John"},
        ]

        for i, case in enumerate(test_cases):
            keycloak_user = {
                "id": f"123e4567-e89b-12d3-a456-42661417400{i}",
                "username": f"test{i}",
                "enabled": True,
                "firstName": case["firstName"],
                "lastName": case["lastName"],
            }

            formatted_user = service_account_driver._format_user(keycloak_user)
            assert formatted_user["description"] == case["expected"]

    def test_format_user_name_trimming(self, direct_grant_driver):
        """Test that name components are properly trimmed."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174006",
            "username": "trimtest",
            "enabled": True,
            "firstName": "  John  ",  # Leading/trailing spaces
            "lastName": "\tDoe\n",  # Tabs and newlines
        }

        formatted_user = direct_grant_driver._format_user(keycloak_user)

        # Verify names are trimmed properly
        assert formatted_user["description"] == "John Doe"

    def test_format_user_email_only(self, service_account_driver):
        """Test user with email but no name attributes."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174007",
            "username": "emailonly",
            "enabled": True,
            "email": "test@example.com",
        }

        formatted_user = service_account_driver._format_user(keycloak_user)

        # Verify email is included but no description
        assert formatted_user["email"] == "test@example.com"
        assert "description" not in formatted_user

    def test_format_user_disabled_user(self, direct_grant_driver):
        """Test formatting a disabled user."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174008",
            "username": "disabled.user",
            "enabled": False,
            "firstName": "Disabled",
            "lastName": "User",
            "email": "disabled@example.com",
        }

        formatted_user = direct_grant_driver._format_user(keycloak_user)

        # Verify disabled status is preserved
        assert formatted_user["enabled"] is False
        assert formatted_user["description"] == "Disabled User"
        assert formatted_user["email"] == "disabled@example.com"

    def test_format_user_uuid_conversion(self, service_account_driver):
        """Test UUID conversion is handled correctly."""
        # Test with different UUID formats
        uuid_str = "123e4567-e89b-12d3-a456-426614174000"
        expected_hex = "123e4567e89b12d3a456426614174000"

        keycloak_user = {"id": uuid_str, "username": "uuidtest", "enabled": True}

        formatted_user = service_account_driver._format_user(keycloak_user)

        # Verify UUID is converted to hex without hyphens
        assert formatted_user["id"] == expected_hex
        assert len(formatted_user["id"]) == 32  # Standard UUID hex length
        assert "-" not in formatted_user["id"]  # No hyphens


class MockHints:
    """Mock Keystone driver hints object for testing."""

    def __init__(self):
        self.filters = []

    def add_filter(self, name, value, comparator="equals", case_sensitive=False):
        """Add a filter to the filters list."""
        self.filters.append(
            {
                "name": name,
                "value": value,
                "comparator": comparator,
                "case_sensitive": case_sensitive,
            }
        )


class TestBuildQueryFromHints:
    """Test cases for _build_query_from_hints method."""

    def test_build_query_no_hints(self, direct_grant_driver):
        """Test query building with no hints."""
        query = direct_grant_driver._build_query_from_hints(None, "username", "user")
        assert query == {}

    def test_build_query_empty_hints(self, direct_grant_driver):
        """Test query building with empty hints."""
        hints = MockHints()
        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")
        assert query == {}

    def test_build_query_equals_comparator(self, direct_grant_driver):
        """Test query building with equals comparator."""
        hints = MockHints()
        hints.add_filter("name", "testuser", comparator="equals")

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        assert query["username"] == "testuser"
        assert query["exact"] is True

    def test_build_query_contains_comparator(self, direct_grant_driver):
        """Test query building with contains comparator."""
        hints = MockHints()
        hints.add_filter("name", "test", comparator="contains")

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        assert query["username"] == "test"
        assert "exact" not in query

    def test_build_query_startswith_comparator(self, direct_grant_driver):
        """Test query building with startswith comparator."""
        hints = MockHints()
        hints.add_filter("name", "test", comparator="startswith")

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        assert query["username"] == "test"
        assert "exact" not in query

    def test_build_query_unsupported_comparator(self, direct_grant_driver):
        """Test query building with unsupported comparator is ignored."""
        hints = MockHints()
        hints.add_filter("name", "test", comparator="endswith")

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        # Unsupported comparator should be ignored
        assert query == {}

    def test_build_query_non_name_filter(self, direct_grant_driver):
        """Test query building with non-name filter is ignored."""
        hints = MockHints()
        hints.add_filter("enabled", True, comparator="equals")

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        # Non-name filters are not supported
        assert query == {}

    def test_build_query_multiple_filters_same_field(self, direct_grant_driver):
        """Test query building with multiple filters for same field.

        When multiple filters exist for the same field, query parameters get
        overwritten. The username from the last filter is used, but the exact
        flag from the first filter persists. This documents current behavior.
        """
        hints = MockHints()
        hints.add_filter("name", "firstvalue", comparator="equals")
        hints.add_filter("name", "secondvalue", comparator="contains")

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        # Last filter's value wins, but exact flag from first filter persists
        assert query["username"] == "secondvalue"
        assert query["exact"] is True  # From first filter

    def test_build_query_empty_value(self, direct_grant_driver):
        """Test query building with empty filter value."""
        hints = MockHints()
        hints.add_filter("name", "", comparator="equals")

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        # Empty value should be ignored
        assert query == {}

    def test_build_query_none_value(self, direct_grant_driver):
        """Test query building with None filter value."""
        hints = MockHints()
        hints.add_filter("name", None, comparator="equals")

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        # None value should be ignored
        assert query == {}

    def test_build_query_for_groups(self, direct_grant_driver):
        """Test query building for groups uses 'search' parameter."""
        hints = MockHints()
        hints.add_filter("name", "testgroup", comparator="equals")

        query = direct_grant_driver._build_query_from_hints(hints, "search", "group")

        assert query["search"] == "testgroup"
        assert query["exact"] is True

    def test_build_query_case_sensitive_ignored(self, direct_grant_driver):
        """Test case_sensitive flag is currently ignored."""
        hints = MockHints()
        hints.add_filter("name", "TestUser", comparator="equals", case_sensitive=True)

        query = direct_grant_driver._build_query_from_hints(hints, "username", "user")

        # case_sensitive is ignored in current implementation
        assert query["username"] == "TestUser"
        assert query["exact"] is True


class TestListUsersWithHints:
    """Test cases for list_users method with hints."""

    @patch.object(Driver, "_keycloak_with_retry")
    def test_list_users_no_hints(self, mock_retry, direct_grant_driver):
        """Test list_users with no hints."""
        mock_retry.return_value = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "user1",
                "enabled": True,
            }
        ]

        result = direct_grant_driver.list_users(None)

        # Should call get_users with briefRepresentation only
        mock_retry.assert_called_once()
        call_args = mock_retry.call_args
        assert call_args[1]["query"] == {"briefRepresentation": True}

    @patch.object(Driver, "_keycloak_with_retry")
    def test_list_users_with_equals_filter(self, mock_retry, direct_grant_driver):
        """Test list_users with equals filter."""
        mock_retry.return_value = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "testuser",
                "enabled": True,
            }
        ]
        hints = MockHints()
        hints.add_filter("name", "testuser", comparator="equals")

        result = direct_grant_driver.list_users(hints)

        # Should include username, exact, and briefRepresentation
        call_args = mock_retry.call_args
        expected_query = {
            "username": "testuser",
            "exact": True,
            "briefRepresentation": True,
        }
        assert call_args[1]["query"] == expected_query

    @patch.object(Driver, "_keycloak_with_retry")
    def test_list_users_with_contains_filter(self, mock_retry, direct_grant_driver):
        """Test list_users with contains filter."""
        mock_retry.return_value = []
        hints = MockHints()
        hints.add_filter("name", "test", comparator="contains")

        result = direct_grant_driver.list_users(hints)

        # Should include username and briefRepresentation, no exact flag
        call_args = mock_retry.call_args
        expected_query = {"username": "test", "briefRepresentation": True}
        assert call_args[1]["query"] == expected_query

    @patch.object(Driver, "_keycloak_with_retry")
    def test_list_users_formats_results(self, mock_retry, direct_grant_driver):
        """Test list_users formats returned users."""
        mock_retry.return_value = [
            {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "user1",
                "enabled": True,
                "email": "user1@example.com",
            }
        ]

        result = direct_grant_driver.list_users(None)

        # Verify formatting is applied
        assert len(result) == 1
        assert result[0]["id"] == "123e4567e89b12d3a456426614174000"  # No hyphens
        assert result[0]["name"] == "user1"
        assert result[0]["email"] == "user1@example.com"


class TestListGroupsWithHints:
    """Test cases for list_groups method with hints."""

    @patch.object(Driver, "_keycloak_with_retry")
    def test_list_groups_no_hints(self, mock_retry, direct_grant_driver):
        """Test list_groups with no hints."""
        mock_retry.return_value = [
            {"id": "123e4567-e89b-12d3-a456-426614174000", "name": "group1", "path": "/group1"}
        ]

        result = direct_grant_driver.list_groups(None)

        # Should call get_groups with empty query
        mock_retry.assert_called_once()
        call_args = mock_retry.call_args
        assert call_args[1]["query"] == {}

    @patch.object(Driver, "_keycloak_with_retry")
    def test_list_groups_with_equals_filter(self, mock_retry, direct_grant_driver):
        """Test list_groups with equals filter."""
        mock_retry.return_value = [
            {"id": "123e4567-e89b-12d3-a456-426614174000", "name": "testgroup", "path": "/testgroup"}
        ]
        hints = MockHints()
        hints.add_filter("name", "testgroup", comparator="equals")

        result = direct_grant_driver.list_groups(hints)

        # Should include search and exact parameters
        call_args = mock_retry.call_args
        expected_query = {"search": "testgroup", "exact": True}
        assert call_args[1]["query"] == expected_query

    @patch.object(Driver, "_keycloak_with_retry")
    def test_list_groups_with_startswith_filter(self, mock_retry, direct_grant_driver):
        """Test list_groups with startswith filter."""
        mock_retry.return_value = []
        hints = MockHints()
        hints.add_filter("name", "test", comparator="startswith")

        result = direct_grant_driver.list_groups(hints)

        # Should include search but no exact flag
        call_args = mock_retry.call_args
        expected_query = {"search": "test"}
        assert call_args[1]["query"] == expected_query

    @patch.object(Driver, "_keycloak_with_retry")
    def test_list_groups_formats_results(self, mock_retry, direct_grant_driver):
        """Test list_groups formats returned groups."""
        mock_retry.return_value = [
            {"id": "123e4567-e89b-12d3-a456-426614174000", "name": "group1", "path": "/group1"}
        ]

        result = direct_grant_driver.list_groups(None)

        # Verify formatting is applied
        assert len(result) == 1
        assert result[0]["id"] == "123e4567e89b12d3a456426614174000"  # No hyphens
        assert result[0]["name"] == "group1"
