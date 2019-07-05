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


def create_tenant(api, configuration, api_version, api_exception, account_name):
    """ Creates a tenant on the primary Deep Security Manager.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param account_name: The account name to use for the tenant.
    :return: A TenantsApi object that contains the new tenant.
    """

    # Define the administrator account
    admin = api.Administrator()
    admin.username = "TenantAdmin"
    admin.password = "Pas$w0rd"
    admin.email_address = "example@email.com"
    admin.receive_notifications = "false"
    admin.role_id = 1

    # Create a tenant
    tenant = api.Tenant(administrator=admin)

    # Set the visible modules
    modules = api.Tenant.modules_visible = ["anti-malware", "firewall", "intrusion-prevention"]
    tenant.modules_visible = modules

    # Set the account name
    tenant.name = account_name

    # Set the locale and description
    tenant.locale = "en-US"
    tenant.description = "Test tenant."

    # Create the tenant on Deep Security Manager
    try:
        tenants_api = api.TenantsApi(api.ApiClient(configuration))
        return tenants_api.create_tenant(tenant, api_version, confirmation_required=False, asynchronous=True)

    except api_exception as e:
        return "Exception: " + str(e)


def get_ip_states_for_tenant(api, configuration, api_version, api_exception, tenant_id):
    """ Obtains the running state of the Intrusion Prevention module for a tenant's computers.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param tenant_id: The ID of the tenant.
    :return: A dictionary that contains computer IDs and the module running state.
    """

    computer_ip_states = {}

    primary_key = configuration.api_key['api-secret-key']

    # Create an API key
    key = api.ApiKey()
    key.key_name = "Temporary API Key"
    key.role_id = 1
    key.locale = "en-US"
    key.time_zone = "Asia/Tokyo"

    try:
        # Check that the tenant is in the 'active' state
        state = api.TenantsApi(api.ApiClient(configuration)).describe_tenant(tenant_id, api_version).tenant_state
        if state == 'active':

            # Generate the secret key for the tenant
            tenants_api = api.TenantsApi(api.ApiClient(configuration))
            generated_key = tenants_api.generate_tenant_api_secret_key(tenant_id, key, api_version)

            # Add the secret key to the configuration
            configuration.api_key['api-secret-key'] = generated_key.secret_key

            # Include Intrusion Prevention information in the returned Computer objects
            expand = api.Expand(api.Expand.intrusion_prevention)

            # Get a list of tenant computers
            computers_api = api.ComputersApi(api.ApiClient(configuration))
            computers_list = computers_api.list_computers(api_version, expand=expand.list(), overrides=False)

            # Find the Intrusion Prevention state for each computer
            for computer in computers_list.computers:
                computer_ip_states[computer.id] = computer.intrusion_prevention.state

            # Reset the API key to the primary key
            configuration.api_key['api-secret-key'] = primary_key

        return computer_ip_states

    except api_exception as e:
        return "Exception: " + str(e)


def get_ip_rules_for_tenant_computers(api, configuration, api_version, api_exception):
    """ Obtains the IDs of the Intrusion Prevention rules that are assigned to each tenant's computers.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A dictionary of tenants IDs that contains a dictionary of computer IDs with the IP rules they are using.
    """

    tenant_rules = {}
    primary_key = configuration.api_key['api-secret-key']

    try:
        tenants_api = api.TenantsApi(api.ApiClient(configuration))
        tenants_list = tenants_api.list_tenants(api_version)

        for tenant in tenants_list.tenants:
            print("Processing tenant " + str(tenant.id))

            #  Check that the tenant is in the 'active' state
            state = api.TenantsApi(api.ApiClient(configuration)).describe_tenant(tenant.id, api_version).tenant_state
            if state == 'active':

                # Create an API key
                key = api.ApiKey()
                key.key_name = "Temporary Key for getting IP rules from tenant computers"
                key.role_id = 1
                key.locale = "en-US"
                key.time_zone = "Asia/Tokyo"

                # Generate the secret key for the tenant
                tenants_api = api.TenantsApi(api.ApiClient(configuration))
                generated_key = tenants_api.generate_tenant_api_secret_key(tenant.id, key, api_version)

                # Add the secret key to the configuration
                configuration.api_key['api-secret-key'] = generated_key.secret_key

                # Include Intrusion Prevention information in the retrieved Computer objects
                expand = api.Expand(api.Expand.intrusion_prevention)

                # Create a ComputersApi object for the tenant
                computers_api = api.ComputersApi(api.ApiClient(configuration))

                # Get a list of computers for the tenant
                computers_list = computers_api.list_computers(api_version, expand=expand.list(), overrides=False)

                # For the tenant, get the IP rules for all computers
                computer_ip_rules = {}
                for computer in computers_list.computers:
                    computer_ip_rules[computer.id] = computer.intrusion_prevention.rule_ids

                tenant_rules[tenant.id] = computer_ip_rules

                # Reset the API key to the primary key
                configuration.api_key['api-secret-key'] = primary_key

        return tenant_rules

    except api_exception as e:
        return "Exception: " + str(e)


def add_policy_to_tenant(api, configuration, api_version, api_exception, policy, tenant_id):
    """ Adds a policy to a tenant.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy: The policy to add to the tenant.
    :param tenant_id: The ID of the tenant.
    :return: A PoliciesApi object that contains the new tenant.
    """

    tenant_client_with_policy = None
    primary_key = configuration.api_key['api-secret-key']

    # Create an API key
    key = api.ApiKey()
    key.key_name = "Temporary key for adding policy to a tenant"
    key.role_id = 1
    key.locale = "en-US"
    key.timeZone = "Asia/Tokyo"

    try:
        # Check that the tenant is in the 'active' state
        state = api.TenantsApi(api.ApiClient(configuration)).describe_tenant(tenant_id, api_version).tenant_state
        if state == 'active':

            # Generate the secret key for the tenant
            tenants_api = api.TenantsApi(api.ApiClient(configuration))
            generated_key = tenants_api.generate_tenant_api_secret_key(tenant_id, key, api_version)

            # Add the secret key to the configuration
            configuration.api_key['api-secret-key'] = generated_key.secret_key

            # Add the policy
            tenant_policies_api = api.PoliciesApi(api.ApiClient(configuration))
            tenant_client_with_policy = tenant_policies_api.create_policy(policy, api_version, overrides=False)

            # Reset the API key to the primary key
            configuration.api_key['api-secret-key'] = primary_key

        return tenant_client_with_policy

    except api_exception as e:
        return "Exception: " + str(e)
