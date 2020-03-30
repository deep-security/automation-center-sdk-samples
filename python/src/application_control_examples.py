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

import time


def configure_application_control(api, configuration, api_version, api_exception, policy_id):
    """ Modifies a policy to set the application control state to on.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The ID of the policy to modify.
    :return: A PoliciesApi object that contains the ID of the modified policy.
    """

    # Get the policy
    policies_api = api.PoliciesApi(api.ApiClient(configuration))

    # Turn on Application Control
    application_control_policy_extension = api.ApplicationControlPolicyExtension()
    application_control_policy_extension.state = "on"

    # Update the policy
    update_policy = api.Policy()
    update_policy.application_control = application_control_policy_extension

    # Modify the policy on Deep Security Manager
    app_control_policy = policies_api.modify_policy(policy_id, update_policy, api_version, overrides=False)
    return app_control_policy


def add_global_rules(sha256_list, api, configuration, api_version, api_exception):
    """ Adds new Global Rules

    :param sha256_list: The list of SHA-256 hashes of the executables to create new rules for.
    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: The list of new rules added.
    """

    # Create the rules
    new_rules = []
    for sha256 in sha256_list:
        new_rule = api.ApplicationControlGlobalRule()
        new_rule.sha256 = sha256
        new_rules.append(new_rule)

    # Add the rules
    global_rules_api = api.GlobalRulesApi(api.ApiClient(configuration))
    rules_list = api.ApplicationControlGlobalRules()
    rules_list.application_control_global_rules = new_rules
    return global_rules_api.add_global_rules(rules_list, api_version)


def block_all_unrecognized_software(computer_id, api, configuration, api_version, api_exception):
    """ Blocks all software changes on a computer.

    :param computer_id: The ID of the computer.
    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A list of SoftwareChangeReviewResult objects.
    """

    # Search for software changes on the computer
    # Search criteria
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "computerID"
    search_criteria.numeric_test = "equal"
    search_criteria.numeric_value = computer_id

    # Add criteria to search filter
    search_filter = api.SearchFilter(None, [search_criteria])

    # Perform the search
    software_changes_api = api.SoftwareChangesApi(api.ApiClient(configuration))
    computer_software_changes = software_changes_api.search_software_changes(api_version, search_filter=search_filter)

    # Block the unrecognized software
    # Create the software change review object and set action to block
    software_change_review = api.SoftwareChangeReview()
    software_change_review.action = "block"
    software_change_review.software_change_ids = []

    # Add the IDs of the software changes to block
    for software_change in computer_software_changes.software_changes:
        software_change_review.software_change_ids.append(software_change.id)

    # Perform the software change review if software changes happened
    if len(software_change_review.software_change_ids) > 0:
        return software_changes_api.review_software_changes(software_change_review, api_version)


def create_shared_ruleset(computer_id, ruleset_name, api, configuration, api_version, api_exception):
    """ Creates a shared ruleset from a computer's software inventory.

    :param computer_id: The ID of the computer.
    :param ruleset_name: The name of the ruleset.
    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A list of SoftwareChangeReviewResult objects.
    """
    software_inventory = api.SoftwareInventory()
    software_inventory.computer_id = computer_id

    # Build software_inventory
    software_inventories_api = api.SoftwareInventoriesApi(
        api.ApiClient(configuration))
    new_inventory = software_inventories_api.create_software_inventory(
        software_inventory, api_version)

    while new_inventory.state != "complete":
        # check status every 30 seconds
        time.sleep(30)
        new_inventory = software_inventories_api.describe_software_inventory(
            new_inventory.id, api_version)

    # Create ruleset
    ruleset = api.Ruleset()
    ruleset.name = ruleset_name
    rulesets_api = api.RulesetsApi(api.ApiClient(configuration))
    return rulesets_api.create_ruleset(ruleset, new_inventory.id, api_version)


def turn_on_maintenance_mode(computer_id, duration, api, configuration, api_version, api_exception):
    """ Turns on maintenance mode on a computer.

    :param computer_id: The ID of the computer.
    :param duration: The maintenance mode duration.
    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A Computer object.
    """

    # Create and configure an ApplicationControlComputerExtesnion object
    application_control = api.ApplicationControlComputerExtension()
    application_control.maintenance_mode_status = "on"
    application_control.maintenance_mode_duration = duration

    # Add the ApplicationControlComputerExtension to a Computer object
    computer = api.Computer()
    computer.application_control = application_control

    # Update the computer
    computers_api = api.ComputersApi(api.ApiClient(configuration))
    return computers_api.modify_computer(computer_id, computer, api_version)
