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

from oslo_config import fixture as config_fixture

from keystone.tests.unit import core
from keystone.tests.unit.identity.backends import test_base

from keystone_keycloak_backend import identity


class TestDriver(core.BaseTestCase, test_base.IdentityDriverTests):
    allows_name_update = False
    allows_self_service_change_password = False
    expected_is_domain_aware = False
    expected_default_assignment_driver = "sql"
    expected_is_sql = False
    expected_generates_uuids = True

    def setUp(self):
        super(TestDriver, self).setUp()

        config_fixture_ = self.useFixture(config_fixture.Config())
        config_fixture_.config(
            group="keycloak",
            server_url="http://localhost:8080/auth",
            username="admin",
            password="password",
            realm_name="master",
            user_realm_name="test",
            client_id="admin-cli",
            verify=False,
        )

        self.driver = identity.Driver()

    # test_authenticate
    # test__format_user
    # test_create_user
    # test_list_users
    # test_unset_default_project_id
    # test_list_users_in_group
    # test_get_user
    # test_update_user
    # test_change_password
    # test_add_user_to_group
    # test_check_user_in_group
    # test_remove_user_from_group
    # test_delete_user
    # test_get_user_by_name
    # test__format_group
    # test__format_groups
    # test_create_group
    # test_list_groups
    # test_list_groups_for_user
    # test_get_group
    # test_get_group_by_name
    # test_update_group
    # test_delete_group
