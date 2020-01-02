# Copyright 2019 Trend Micro.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

def search_roles_by_name(api, configuration, api_version, api_exception, role_name):
    """ Searches for a role by name and returns the ID.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param role_name: The role name to search.
    :return: The ID of the found role, or None if no role is found.
    """

    # Store the role ID - default is None
    role_id = None
    
    # Search criteria
    name_criteria = api.SearchCriteria()
    name_criteria.field_name = "name"
    name_criteria.string_value = role_name
    name_criteria.string_test = "equal"

    # Search filter
    role_filter = api.SearchFilter()
    role_filter.search_criteria = [name_criteria]

    # Perform the search and obtain the ID of the returned role
    # Perform the search
    admin_roles_api = api.AdministratorRolesApi(api.ApiClient(configuration))
    roles = admin_roles_api.search_administrator_roles(api_version, search_filter=role_filter)

    if len(roles.roles) > 0:
        role_id = roles.roles[0].id

    return role_id


def create_role_for_computer_reports(api, configuration, api_version, api_exception):
    """ Creates a role with rights that are appropriate for reading computer properties and assigning policies to computers.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: The ID of the new role.
    """

    # Create the Role object
    run_reports_role = api.Role()
    run_reports_role.name = "Computer Status and Properties"

    # No need for access to policies
    run_reports_role.all_policies = False

    # Add rights to edit computer properties
    computer_rights = api.ComputerRights()
    computer_rights.can_edit_computer_properties = True

    platform_rights = api.PlatformRights()
    platform_rights.computer_rights = computer_rights

    rights = api.Rights()
    rights.platform_rights = platform_rights

    # Add the rights to the role
    run_reports_role.rights = rights

    # Create the role on Deep Security Manager
    # Perform the search
    admin_roles_api = api.AdministratorRolesApi(api.ApiClient(configuration))
    new_role = admin_roles_api.create_administrator_role(run_reports_role, api_version)

    return new_role.id
