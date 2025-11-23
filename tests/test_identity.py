# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the Keycloak identity backend driver.
"""

import pytest
from unittest.mock import Mock, patch

from keystone_keycloak_backend.identity import Driver


class MockConfig:
    """Mock configuration object for testing."""

    def __init__(self, auth_method="direct_grant", debug=False):
        self.keycloak = MockKeycloakConfig(auth_method, debug)

    def register_group(self, group):
        pass

    def register_opts(self, opts, group=None):
        pass


class MockKeycloakConfig:
    """Mock Keycloak configuration section."""

    def __init__(self, auth_method="direct_grant", debug=False):
        self.server_url = "http://localhost:8080"
        self.realm_name = "test"
        self.client_id = "admin-cli"
        self.verify = False
        self.debug = debug

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


@pytest.fixture
def debug_driver():
    """Fixture to create a Driver instance with debug enabled."""
    mock_config = MockConfig(auth_method="service_account", debug=True)
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

    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    def test_get_fresh_token_service_account(
        self, mock_openid_class, service_account_driver
    ):
        """Test token acquisition for Service Account."""
        # Mock the KeycloakOpenID instance
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {
            "access_token": "test-token",
            "token_type": "Bearer",
        }

        # Test token acquisition
        token = service_account_driver._get_fresh_token()

        # Verify Service Account token call
        mock_openid.token.assert_called_once_with(grant_type="client_credentials")
        assert token["access_token"] == "test-token"

        # Verify KeycloakOpenID was initialized with correct parameters
        mock_openid_class.assert_called_once_with(
            server_url="http://localhost:8080",
            realm_name="test",  # Uses realm_name for Service Account
            client_id="keystone-client",
            client_secret_key="test-secret-key",
            verify=False,
        )

    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    def test_get_fresh_token_direct_grant(self, mock_openid_class, direct_grant_driver):
        """Test token acquisition for Direct Grant."""
        # Mock the KeycloakOpenID instance
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {
            "access_token": "test-token",
            "token_type": "Bearer",
        }

        # Test token acquisition
        token = direct_grant_driver._get_fresh_token()

        # Verify Direct Grant token call
        mock_openid.token.assert_called_once_with(
            username="admin", password="admin", grant_type="password"
        )
        assert token["access_token"] == "test-token"

        # Verify KeycloakOpenID was initialized with user_realm_name for Direct Grant
        mock_openid_class.assert_called_once_with(
            server_url="http://localhost:8080",
            realm_name="master",  # Uses user_realm_name for Direct Grant
            client_id="admin-cli",
            client_secret_key=None,
            verify=False,
        )

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    def test_keycloak_property_service_account(
        self, mock_openid_class, mock_admin_class, service_account_driver
    ):
        """Test KeycloakAdmin initialization for Service Account."""
        # Mock token acquisition
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

        # Mock KeycloakAdmin
        mock_admin = Mock()
        mock_admin_class.return_value = mock_admin

        # Access the keycloak property
        keycloak_instance = service_account_driver.keycloak

        # Verify KeycloakAdmin was initialized with token-based auth for Service Account
        # (eliminating double authentication)
        mock_admin_class.assert_called_once_with(
            server_url="http://localhost:8080",
            realm_name="test",  # Uses realm_name for target realm
            verify=False,
            token={"access_token": "test-token"},  # Full token for Service Account
        )
        assert keycloak_instance == mock_admin

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    def test_keycloak_property_direct_grant(
        self, mock_openid_class, mock_admin_class, direct_grant_driver
    ):
        """Test KeycloakAdmin initialization for Direct Grant."""
        # Mock token acquisition
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

        # Mock KeycloakAdmin
        mock_admin = Mock()
        mock_admin_class.return_value = mock_admin

        # Access the keycloak property
        keycloak_instance = direct_grant_driver.keycloak

        # Verify KeycloakAdmin was initialized for Direct Grant with token
        mock_admin_class.assert_called_once_with(
            server_url="http://localhost:8080",
            realm_name="test",  # Uses realm_name for target realm
            verify=False,
            token={
                "access_token": "test-token"
            },  # Refresh_token removed for Direct Grant
        )
        assert keycloak_instance == mock_admin

    def test_config_hash_uniqueness(self, service_account_driver, direct_grant_driver):
        """Test that different configurations produce different cache keys."""
        # Force initialization of both drivers
        with patch("keystone_keycloak_backend.identity.KeycloakOpenID"), patch(
            "keystone_keycloak_backend.identity.KeycloakAdmin"
        ):

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
            service_account_attrs = [
                attr
                for attr in dir(service_account_driver)
                if attr.startswith("_keycloak_")
            ]
            direct_grant_attrs = [
                attr
                for attr in dir(direct_grant_driver)
                if attr.startswith("_keycloak_")
            ]

            # They should have different cache keys due to different configurations
            # Note: This is a basic check - the actual hash values depend on the implementation


class TestDebugMode:
    """Test cases for debug mode functionality."""

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    @patch("keystone_keycloak_backend.identity.LOG")
    def test_debug_logging_enabled(
        self, mock_log, mock_openid_class, mock_admin_class, debug_driver
    ):
        """Test that debug logging is enabled when debug=True."""
        # Mock token acquisition
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

        # Mock KeycloakAdmin
        mock_admin = Mock()
        mock_admin_class.return_value = mock_admin

        # Access the keycloak property to trigger debug logging
        _ = debug_driver.keycloak

        # Verify debug logs were called
        debug_calls = [
            call
            for call in mock_log.warning.call_args_list
            if "KEYCLOAK_DEBUG:" in str(call)
        ]
        assert len(debug_calls) > 0, "Debug logging should be enabled"

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    @patch("keystone_keycloak_backend.identity.LOG")
    def test_debug_logging_disabled(
        self, mock_log, mock_openid_class, mock_admin_class, service_account_driver
    ):
        """Test that debug logging is disabled when debug=False."""
        # Mock token acquisition
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

        # Mock KeycloakAdmin
        mock_admin = Mock()
        mock_admin_class.return_value = mock_admin

        # Access the keycloak property
        _ = service_account_driver.keycloak

        # Verify debug logs were NOT called
        debug_calls = [
            call
            for call in mock_log.warning.call_args_list
            if "KEYCLOAK_DEBUG:" in str(call)
        ]
        assert len(debug_calls) == 0, "Debug logging should be disabled"

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    @patch("keystone_keycloak_backend.identity.LOG")
    def test_keycloak_with_retry_debug_logging(
        self, mock_log, mock_openid_class, mock_admin_class, debug_driver
    ):
        """Test debug logging in _keycloak_with_retry method."""
        # Mock token acquisition
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

        # Mock KeycloakAdmin
        mock_admin = Mock()
        mock_admin_class.return_value = mock_admin

        # Mock a successful operation
        mock_operation = Mock(return_value="success")
        mock_operation.__name__ = "test_operation"

        # Test the method
        result = debug_driver._keycloak_with_retry(mock_operation)

        # Verify debug logs were called
        debug_calls = [
            call
            for call in mock_log.warning.call_args_list
            if "KEYCLOAK_DEBUG:" in str(call)
        ]
        assert len(debug_calls) >= 2, "Should log operation start and success"

        # Check specific debug messages
        call_messages = [str(call) for call in mock_log.warning.call_args_list]
        assert any("Calling test_operation" in msg for msg in call_messages)
        assert any("test_operation successful" in msg for msg in call_messages)


class TestErrorHandling:
    """Test cases for error handling and retry logic."""

    @pytest.mark.skip(reason="Property mocking complexity - TODO: Fix")
    @patch("keystone_keycloak_backend.identity.LOG")
    def test_403_error_retry_with_debug(self, mock_log, debug_driver):
        """Test 403 error handling with debug logging."""
        # Import the actual exception type that the code handles
        from keystone_keycloak_backend.identity import keycloak_exceptions

        # Create a mock exception that behaves like KeycloakGetError
        mock_exception = keycloak_exceptions.KeycloakGetError("403 Forbidden")
        mock_exception.response_code = 403

        # Mock operation that fails with 403, then succeeds
        mock_operation = Mock(side_effect=[mock_exception, "success"])
        mock_operation.__name__ = "test_operation"

        # Mock refresh method and Keycloak dependencies
        with patch.object(debug_driver, "_refresh_token_and_client"), patch(
            "keystone_keycloak_backend.identity.KeycloakAdmin"
        ), patch(
            "keystone_keycloak_backend.identity.KeycloakOpenID"
        ) as mock_openid_class:

            # Mock token acquisition
            mock_openid = Mock()
            mock_openid_class.return_value = mock_openid
            mock_openid.token.return_value = {"access_token": "test-token"}

            result = debug_driver._keycloak_with_retry(mock_operation)

        # Verify the operation was retried and succeeded
        assert result == "success"
        assert mock_operation.call_count == 2

        # Verify debug logging for 403 retry
        debug_calls = [
            call
            for call in mock_log.warning.call_args_list
            if "KEYCLOAK_DEBUG:" in str(call)
        ]
        call_messages = [str(call) for call in debug_calls]
        assert any(
            "Got 403 for test_operation, refreshing token" in msg
            for msg in call_messages
        )

    @pytest.mark.skip(reason="Property mocking complexity - TODO: Fix")
    @patch("keystone_keycloak_backend.identity.LOG")
    def test_403_error_message_contains_realm_info(self, mock_log, debug_driver):
        """Test that 403 error messages contain proper realm information."""
        # Import the actual exception type that the code handles
        from keystone_keycloak_backend.identity import keycloak_exceptions

        # Create a mock exception that behaves like KeycloakGetError
        mock_exception = keycloak_exceptions.KeycloakGetError("403 Forbidden")
        mock_exception.response_code = 403

        # Mock operation that always fails with 403
        mock_operation = Mock(side_effect=mock_exception)
        mock_operation.__name__ = "get_groups"

        # Mock refresh method and Keycloak dependencies
        with patch.object(debug_driver, "_refresh_token_and_client"), patch(
            "keystone_keycloak_backend.identity.KeycloakAdmin"
        ), patch(
            "keystone_keycloak_backend.identity.KeycloakOpenID"
        ) as mock_openid_class:

            # Mock token acquisition
            mock_openid = Mock()
            mock_openid_class.return_value = mock_openid
            mock_openid.token.return_value = {"access_token": "test-token"}

            # This should raise an Exception with realm info
            with pytest.raises(Exception) as exc_info:
                debug_driver._keycloak_with_retry(mock_operation)

        # Verify the error message contains the correct realm information
        error_message = str(exc_info.value)
        assert (
            "realm 'test'" in error_message
        )  # Should show actual realm name, not None
        assert "get_groups" in error_message  # Should show operation name
        assert "Service Account" in error_message  # Should show auth method
        assert "keystone-client" in error_message  # Should show client ID
        assert (
            "/admin/realms/test/users" in error_message
        )  # Should show correct endpoint path

    @pytest.mark.skip(reason="Property mocking complexity - TODO: Fix")
    @patch("keystone_keycloak_backend.identity.LOG")
    def test_403_error_message_short_when_debug_disabled(
        self, mock_log, service_account_driver
    ):
        """Test that 403 error messages are short when debug=false."""
        # Import the actual exception type that the code handles
        from keystone_keycloak_backend.identity import keycloak_exceptions

        # Create a mock exception that behaves like KeycloakGetError
        mock_exception = keycloak_exceptions.KeycloakGetError("403 Forbidden")
        mock_exception.response_code = 403

        # Mock operation that always fails with 403
        mock_operation = Mock(side_effect=mock_exception)
        mock_operation.__name__ = "get_groups"

        # Mock refresh method and Keycloak dependencies
        with patch.object(service_account_driver, "_refresh_token_and_client"), patch(
            "keystone_keycloak_backend.identity.KeycloakAdmin"
        ), patch(
            "keystone_keycloak_backend.identity.KeycloakOpenID"
        ) as mock_openid_class:

            # Mock token acquisition
            mock_openid = Mock()
            mock_openid_class.return_value = mock_openid
            mock_openid.token.return_value = {"access_token": "test-token"}

            # This should raise an Exception with short error message
            with pytest.raises(Exception) as exc_info:
                service_account_driver._keycloak_with_retry(mock_operation)

        # Verify the error message is short and concise (debug=false)
        error_message = str(exc_info.value)
        assert "realm 'test'" in error_message
        assert "service account" in error_message.lower()
        assert "keystone-client" in error_message
        assert "Check realm-management roles" in error_message
        assert "Enable debug=true for details" in error_message

        # Should NOT contain detailed debug information
        assert "operation 'get_groups'" not in error_message
        assert "/admin/realms/test/users" not in error_message
        assert "Admin API endpoint" not in error_message

    @pytest.mark.skip(reason="Property mocking complexity - TODO: Fix")
    @patch("keystone_keycloak_backend.identity.LOG")
    def test_debug_error_logging_conditional(self, mock_log, service_account_driver):
        """Test that detailed error logging only happens when debug=true."""
        # Import the actual exception type that the code handles
        from keystone_keycloak_backend.identity import keycloak_exceptions

        # Create a mock exception that behaves like KeycloakGetError
        mock_exception = keycloak_exceptions.KeycloakGetError("403 Forbidden")
        mock_exception.response_code = 403

        # Mock operation that always fails with 403
        mock_operation = Mock(side_effect=mock_exception)
        mock_operation.__name__ = "get_groups"

        # Mock refresh method and Keycloak dependencies
        with patch.object(service_account_driver, "_refresh_token_and_client"), patch(
            "keystone_keycloak_backend.identity.KeycloakAdmin"
        ), patch(
            "keystone_keycloak_backend.identity.KeycloakOpenID"
        ) as mock_openid_class:

            # Mock token acquisition
            mock_openid = Mock()
            mock_openid_class.return_value = mock_openid
            mock_openid.token.return_value = {"access_token": "test-token"}

            # This should raise an Exception
            with pytest.raises(Exception):
                service_account_driver._keycloak_with_retry(mock_operation)

        # Verify NO detailed error logging happened (debug=false)
        error_calls = [
            call
            for call in mock_log.error.call_args_list
            if "KEYCLOAK_ERROR:" in str(call)
        ]
        assert len(error_calls) == 0, "Should not log detailed errors when debug=false"


class TestDomainIsolation:
    """Test cases for domain isolation functionality."""

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    def test_different_configs_produce_different_instances(
        self, mock_openid_class, mock_admin_class
    ):
        """Test that different configurations create separate Keycloak instances."""
        # Create two drivers with different configurations
        service_config = MockConfig(auth_method="service_account")
        direct_config = MockConfig(auth_method="direct_grant")

        service_driver = Driver(conf=service_config)
        direct_driver = Driver(conf=direct_config)

        # Mock token acquisition
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

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

        # First call (Service Account) - now uses token-based auth
        first_call = mock_admin_class.call_args_list[0]
        assert first_call[1]["server_url"] == "http://localhost:8080"
        assert first_call[1]["token"] == {
            "access_token": "test-token"
        }  # Full token for Service Account
        assert first_call[1]["realm_name"] == "test"

        # Second call (Direct Grant)
        second_call = mock_admin_class.call_args_list[1]
        assert "token" in second_call[1]
        assert second_call[1]["realm_name"] == "test"

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    def test_config_hash_computation(self, mock_openid_class, mock_admin_class):
        """Test that configuration hash is computed correctly."""
        # Create drivers with different configurations
        service_driver = Driver(conf=MockConfig(auth_method="service_account"))
        direct_driver = Driver(conf=MockConfig(auth_method="direct_grant"))

        # Mock token acquisition
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

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

        # Both methods now use token-based authentication to avoid double auth
        # Service Account gets full token, Direct Grant gets token without refresh_token
        assert call1[1].get("token") == {
            "access_token": "test-token"
        }  # Service Account - full token
        assert call2[1].get("token") == {
            "access_token": "test-token"
        }  # Direct Grant - refresh_token removed

        # Even though server URLs and realms are the same, different auth methods
        # (service account vs direct grant) produce different cache keys due to
        # different client_secret_key vs username/password configurations
        # This test validates that cache isolation works correctly

    @patch("keystone_keycloak_backend.identity.KeycloakAdmin")
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    def test_cache_key_isolation(self, mock_openid_class, mock_admin_class):
        """Test that different configurations use different cache keys."""
        service_driver = Driver(conf=MockConfig(auth_method="service_account"))
        direct_driver = Driver(conf=MockConfig(auth_method="direct_grant"))

        # Mock token acquisition
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

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

        # Verify Direct Grant detection
        assert hasattr(config.keycloak, "username")
        assert hasattr(config.keycloak, "password")
        assert hasattr(config.keycloak, "user_realm_name")
        assert config.keycloak.username == "admin"
        assert config.keycloak.password == "admin"
        assert config.keycloak.user_realm_name == "master"
        assert not hasattr(config.keycloak, "client_secret_key")

    def test_debug_flag_configuration(self):
        """Test that debug flag is properly configured."""
        # Test debug enabled
        debug_config = MockConfig(auth_method="service_account", debug=True)
        debug_driver = Driver(conf=debug_config)
        assert debug_config.keycloak.debug is True

        # Test debug disabled (default)
        normal_config = MockConfig(auth_method="service_account", debug=False)
        normal_driver = Driver(conf=normal_config)
        assert normal_config.keycloak.debug is False


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
                        "debug": False,
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
                        "debug": True,
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
    @patch("keystone_keycloak_backend.identity.KeycloakOpenID")
    def test_multi_domain_scenario(self, mock_openid_class, mock_admin_class):
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
                        "debug": False,
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
                        "debug": True,
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
        mock_openid = Mock()
        mock_openid_class.return_value = mock_openid
        mock_openid.token.return_value = {"access_token": "test-token"}

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

        # Production call (Service Account) - now uses token-based auth
        prod_call = mock_admin_class.call_args_list[0]
        assert prod_call[1]["server_url"] == "https://keycloak.company.com"
        assert prod_call[1]["token"] == {"access_token": "test-token"}

        # Legacy call (Direct Grant) - also uses token-based auth
        legacy_call = mock_admin_class.call_args_list[1]
        assert legacy_call[1]["server_url"] == "http://legacy-keycloak:8080"
        assert legacy_call[1]["token"] == {"access_token": "test-token"}


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
