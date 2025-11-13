# Copyright (c) 2025 VEXXHOST, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the Keycloak identity backend driver.
"""

import pytest

from keystone_keycloak_backend.identity import Driver


class MockConfig:
    """Mock configuration object for testing."""

    def __init__(self):
        self.keycloak = MockKeycloakConfig()

    def register_group(self, group):
        pass

    def register_opts(self, opts, group=None):
        pass


class MockKeycloakConfig:
    """Mock Keycloak configuration section."""

    def __init__(self):
        self.server_url = "http://localhost:8080"
        self.username = "admin"
        self.password = "admin"
        self.realm_name = "master"
        self.user_realm_name = "master"
        self.client_id = "admin-cli"
        self.verify = True


@pytest.fixture
def driver():
    """Fixture to create a Driver instance with mock configuration."""
    mock_config = MockConfig()
    return Driver(conf=mock_config)


class TestFormatUser:
    """Test cases for the _format_user method."""

    def test_format_user_with_complete_attributes(self, driver):
        """Test user with all additional attributes (firstName, lastName, email)."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "username": "john.doe",
            "enabled": True,
            "firstName": "John",
            "lastName": "Doe",
            "email": "john.doe@example.com",
        }

        formatted_user = driver._format_user(keycloak_user)

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

    def test_format_user_minimal_attributes(self, driver):
        """Test user with only required attributes (no firstName, lastName, email)."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174001",
            "username": "jane.smith",
            "enabled": True,
        }

        formatted_user = driver._format_user(keycloak_user)

        # Verify core attributes
        assert formatted_user["id"] == "123e4567e89b12d3a456426614174001"
        assert formatted_user["name"] == "jane.smith"
        assert formatted_user["enabled"] is True
        assert formatted_user["password_expires_at"] is None
        assert formatted_user["options"] == {}

        # Verify optional attributes are not present
        assert "description" not in formatted_user
        assert "email" not in formatted_user

    def test_format_user_partial_name(self, driver):
        """Test user with only firstName (no lastName)."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174002",
            "username": "bob.wilson",
            "enabled": False,
            "firstName": "Bob",
            "email": "bob@company.com",
        }

        formatted_user = driver._format_user(keycloak_user)

        # Verify firstName becomes description when lastName is missing
        assert formatted_user["description"] == "Bob"
        assert formatted_user["email"] == "bob@company.com"
        assert formatted_user["enabled"] is False

    def test_format_user_lastname_only(self, driver):
        """Test user with only lastName (no firstName)."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174003",
            "username": "wilson",
            "enabled": True,
            "lastName": "Wilson",
        }

        formatted_user = driver._format_user(keycloak_user)

        # Verify lastName becomes description when firstName is missing
        assert formatted_user["description"] == "Wilson"
        assert "email" not in formatted_user

    def test_format_user_empty_and_null_names(self, driver):
        """Test user with empty string and None name values."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174004",
            "username": "alice.brown",
            "enabled": True,
            "firstName": "",  # Empty string
            "lastName": None,  # None value
            "email": "alice@test.com",
        }

        formatted_user = driver._format_user(keycloak_user)

        # Verify empty/null name values don't create description
        assert "description" not in formatted_user
        assert formatted_user["email"] == "alice@test.com"

    def test_format_user_whitespace_only_names(self, driver):
        """Test user with whitespace-only name values."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174005",
            "username": "charlie",
            "enabled": True,
            "firstName": "   ",  # Whitespace only
            "lastName": "\t\n",  # Tabs and newlines
        }

        formatted_user = driver._format_user(keycloak_user)

        # Verify whitespace-only values don't create description
        assert "description" not in formatted_user

    def test_format_user_mixed_valid_invalid_names(self, driver):
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

            formatted_user = driver._format_user(keycloak_user)
            assert formatted_user["description"] == case["expected"]

    def test_format_user_name_trimming(self, driver):
        """Test that name components are properly trimmed."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174006",
            "username": "trimtest",
            "enabled": True,
            "firstName": "  John  ",  # Leading/trailing spaces
            "lastName": "\tDoe\n",  # Tabs and newlines
        }

        formatted_user = driver._format_user(keycloak_user)

        # Verify names are trimmed properly
        assert formatted_user["description"] == "John Doe"

    def test_format_user_email_only(self, driver):
        """Test user with email but no name attributes."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174007",
            "username": "emailonly",
            "enabled": True,
            "email": "test@example.com",
        }

        formatted_user = driver._format_user(keycloak_user)

        # Verify email is included but no description
        assert formatted_user["email"] == "test@example.com"
        assert "description" not in formatted_user

    def test_format_user_disabled_user(self, driver):
        """Test formatting a disabled user."""
        keycloak_user = {
            "id": "123e4567-e89b-12d3-a456-426614174008",
            "username": "disabled.user",
            "enabled": False,
            "firstName": "Disabled",
            "lastName": "User",
            "email": "disabled@example.com",
        }

        formatted_user = driver._format_user(keycloak_user)

        # Verify disabled status is preserved
        assert formatted_user["enabled"] is False
        assert formatted_user["description"] == "Disabled User"
        assert formatted_user["email"] == "disabled@example.com"

    def test_format_user_uuid_conversion(self, driver):
        """Test UUID conversion is handled correctly."""
        # Test with different UUID formats
        uuid_str = "123e4567-e89b-12d3-a456-426614174000"
        expected_hex = "123e4567e89b12d3a456426614174000"

        keycloak_user = {"id": uuid_str, "username": "uuidtest", "enabled": True}

        formatted_user = driver._format_user(keycloak_user)

        # Verify UUID is converted to hex without hyphens
        assert formatted_user["id"] == expected_hex
        assert len(formatted_user["id"]) == 32  # Standard UUID hex length
        assert "-" not in formatted_user["id"]  # No hyphens
