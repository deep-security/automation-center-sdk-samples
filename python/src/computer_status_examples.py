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

def check_anti_malware(api, configuration, api_version, api_exception, computer_id):
    """ Obtains certain anti-malware properties for a computer.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param computer_id: The ID of the computer.
    :return: An AntiMalwareConfigurationsApi object that contains the anti-malware properties of the computer.
    """

    # Get the computer object from Deep Security Manager
    computers_api = api.ComputersApi(api.ApiClient(configuration))
    computer = computers_api.describe_computer(computer_id, api_version)

    # Get the anti-malware scan configuration id for the computer
    real_time_scan_configuration_id = computer.anti_malware.real_time_scan_configuration_id

    try:
        # Get the anti-malware properties for the computer
        am_configs_api = api.AntiMalwareConfigurationsApi(api.ApiClient(configuration))
        return am_configs_api.describe_anti_malware(real_time_scan_configuration_id, api_version)

    except api_exception as e:
        return "Exception: " + str(e)



def find_rules_for_cve(api, configuration, api_version, api_exception, cve_id):
    """ Finds the intrusion prevention rules for a CVE.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param cve_id: The ID of the CVE.
    :return: The intrusion prevention rule ID, or None if no rule is found.
    """

    rule_id_s = []

    # Set search criteria
    search_criteria = api.SearchCriteria()
    search_criteria.field_name = "CVE"
    search_criteria.string_value = "%" + cve_id + "%"
    search_criteria.string_test = "equal"

    # Create a search filter
    search_filter = api.SearchFilter()
    search_filter.search_criteria = [search_criteria]

    try:
        # Search for all intrusion prevention rules for the CVE
        ip_rules_api = api.IntrusionPreventionRulesApi(api.ApiClient(configuration))
        ip_rules_search_results = ip_rules_api.search_intrusion_prevention_rules(api_version, search_filter=search_filter)

        # Get the intrusion prevention rule IDs for the CVE from the results
        for rule in ip_rules_search_results.intrusion_prevention_rules:
            rule_id_s.append(rule.id)

        return rule_id_s

    except api_exception as e:
        return "Exception: " + str(e)


def check_computers_for_ip_rule(api, configuration, api_version, api_exception, rule_id):
    """ Finds computers that do not have a specific intrusion prevention rule applied.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param rule_id: The ID of the rule.
    :return: A list of computers that do not have the rule applied.
    """

    unprotected_computers = []

    try:
        # Create a list of computers
        computers_api = api.ComputersApi(api.ApiClient(configuration))
        computers_list = computers_api.list_computers(api_version, overrides=False)

        # Search the list of computers for those that do not have the IP rule
        for computer in computers_list.computers:
            computer_ip_list = computer.intrusion_prevention
            if computer_ip_list.rule_ids:
                if rule_id in computer_ip_list.rule_ids:
                    unprotected_computers.append(computer)
        return unprotected_computers

    except api_exception as e:
        return "Exception: " + str(e)

def apply_rule_to_policies(api, configuration, api_version, api_exception, computers, rule_id):
    """ Adds an Intrusion Prevention rule to the policies of a list of computers.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param computer: The Computer that is assigned the policy.
    :param rule_id: The ID of the Intrusion Prevention rule to add.
    :return: A list of PoliciesApi objects that were updated with the rule.
    """


    # Store IDs of policies to modify
    policy_ids = []
    for computer in computers:
        if computer.policy_id:
            policy_ids.append(computer.policy_id)

    # Store modified policies
    modified_policies = []

    for policy_id in policy_ids:
        try:
            # Get the current list of rules from the policy
            policies_api = api.PoliciesApi(api.ApiClient(configuration))
            current_rules = policies_api.describe_policy(policy_id, api_version, overrides=False)

            # Add the rule_id if it doesn't already exist in current_rules
            if current_rules.intrusion_prevention.rule_ids == None:
                current_rules.intrusion_prevention.rule_ids = rule_id

            elif rule_id not in current_rules.intrusion_prevention.rule_ids:
                current_rules.intrusion_prevention.rule_ids.append(rule_id)


            # Add the new and existing intrusion prevention rules to a policy
            intrusion_prevention_policy_extension = api.IntrusionPreventionPolicyExtension()
            intrusion_prevention_policy_extension.rule_ids = current_rules.intrusion_prevention.rule_ids
            policy = api.Policy()
            policy.intrusion_prevention = intrusion_prevention_policy_extension

            # Configure sending policy updates when the policy changes
            policy.auto_requires_update = "on"

            # Modify the policy on Deep Security Manager
            modified_policies.append(policies_api.modify_policy(policy_id, policy, api_version))

        except api_exception as e:
            return "Exception: " + str(e)

    return modified_policies


def get_intrusion_prevention_recommendations(api, configuration, api_version, api_exception, computer_id):
    """Obtains the list of recommended intrusion prevention rules to apply to a computer, according to the results of the last recommendation scan.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param computer_id: The ID of the computer that was scanned.
    :return: A list of recommended Intrusion Prevention rules to apply to a computer,
    according to the results of the last recommendation scan or None if no scan was performed.
    """

    ip_recommendations_api = api.ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi(api.ApiClient(configuration))
    ip_assignments = None

    try:
        ip_assignments = ip_recommendations_api.list_intrusion_prevention_rule_ids_on_computer(computer_id, api_version, overrides=False)
        return ip_assignments.recommended_to_assign_rule_ids

    except api_exception as e:
        return "Exception: " + str(e)



def get_computer_statuses(api, configuration, api_version, api_exception):
    """Obtains agent and appliance status for all computers and provides the results as comma-separated values.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A string that can be saved as a CSV file.
    """

    # Add column titles to comma-separated values string
    csv = "Host Name,Agent or Appliance,Status,Status Messages,Tasks\r\n"

    try:
        computers_api = api.ComputersApi(api.ApiClient(configuration))
        computers = computers_api.list_computers(api_version, overrides=False)

        for computer in computers.computers:
            computer_info = []

            # Report on computers with no agent or appliance
            if computer.agent_finger_print == None and computer.appliance_finger_print == None:
                # Hostname and protection type
                computer_info.append(computer.host_name)
                computer_info.append("None")

                # Agent/appliance status and status messages
                computer_info.append("No agent/appliance")
                status_messages = ""
                if computer.computer_status != None and computer.computer_status.agent_status != None:
                    status_messages = str(computer.computer_status.agent_status_messages)
                computer_info.append(status_messages)

                # Add the computer info to the CSV string
                csv_line = ""
                for num, item in enumerate(computer_info):
                    csv_line += item
                    if num != (len(computer_info) - 1):
                        csv_line += ","
                    else:
                        csv_line += "\r\n"
                csv += csv_line

            else:
                # Report on problem agents and appliances
                agent_status = computer.computer_status.agent_status
                appliance_status = computer.computer_status.appliance_status

                # Agent is installed but is not active
                if computer.agent_finger_print != None and agent_status != "active":
                    # Hostname and protection type
                    computer_info.append(computer.host_name)
                    computer_info.append("Agent")

                    # Agent status, status messages, and tasks
                    if computer.computer_status.agent_status != None:
                        computer_info.append(computer.computer_status.agent_status)
                    else:
                        computer_info.append("")

                    if computer.computer_status.agent_status_messages != None:
                        computer_info.append(str(computer.computer_status.agent_status_messages))
                    else:
                        computer_info.append("")

                    if computer.tasks != None:
                        computer_info.append(str(computer.tasks.agent_tasks))
                    else:
                        computer_info.append("")

                    # Add the computer info to the CSV string
                    csv_line = ""
                    for num, item in enumerate(computer_info):
                        csv_line += item
                        if num != (len(computer_info) - 1):
                            csv_line += ","
                        else:
                            csv_line += "\r\n"
                    csv += csv_line

                # Appliance is installed but is not active
                if computer.appliance_finger_print != None and appliance_status != "active":
                    # Hostname and protection type
                    computer_info.append(computer.host_name)
                    computer_info.append("Appliance")

                    # Appliance status, status messages, and tasks
                    if computer.computer_status.appliance_status != None:
                        computer_info.append(computer.computer_status.appliance_status)
                    else:
                        computer_info.append("")

                    if computer.computer_status.appliance_status_messages != None:
                        computer_info.append(str(computer.computer_status.appliance_status_messages))
                    else:
                        computer_info.append("")

                    if computer.tasks != None:
                        computer_info.append(str(computer.tasks.appliance_tasks))
                    else:
                        computer_info.append("")

                    # Add the computer info to the CSV string
                    csv_line = ""
                    for num, item in enumerate(computer_info):
                        csv_line += item
                        if num != (len(computer_info) - 1):
                            csv_line += ","
                        else:
                            csv_line += "\r\n"
                    csv += csv_line

        return csv

    except api_exception as e:
        return "Exception: " + str(e)



def get_anti_malware_status_for_computers(api, configuration, api_version, api_exception):
    """Obtains agent and appliance status for the Anti-Malware module of all computers.

    Returns the status information of all computers that have the Anti-Malware module turned off,
    or where the status of the module is not active as comma-separated values.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A string that can be saved as a CSV file.
    """

    # Add column titles to comma-separated values string
    csv = "Host Name,Module State,Agent or Appliance,Status,Status Message\r\n"

    try:
        computers_api = api.ComputersApi(api.ApiClient(configuration))
        computers = computers_api.list_computers(api_version, overrides=False)

        # Get the list of computers and iterate over it
        for computer in computers.computers:
            # Module information to add to the CSV string
            module_info = []

            # Check that the computer has a an agent or appliance status
            if computer.anti_malware.module_status:
                agent_status = computer.anti_malware.module_status.agent_status
                appliance_status = computer.anti_malware.module_status.appliance_status
            else:
                agent_status = None
                appliance_status = None

            # Agents that are not active for the module
            if agent_status and agent_status != "active":
                # Host name
                module_info.append(computer.host_name)

                # Module state
                module_info.append(computer.anti_malware.state)

                # Agent status and status message
                module_info.append("Agent")
                module_info.append(agent_status)
                module_info.append(computer.anti_malware.module_status.agent_status_message)

                # Add the module info to the CSV string
                csv_line = ""
                for num, item in enumerate(module_info):
                    csv_line += item
                    if num != (len(module_info) - 1):
                        csv_line += ","
                    else:
                        csv_line += "\r\n"
                csv += csv_line

            # Appliances that are not active for the module
            if appliance_status and appliance_status != "active":
                # Host name
                module_info.append(computer.host_name)
        
                # Module state
                module_info.append(computer.anti_malware.state)
        
                # Appliance status and status message
                module_info.append("Appliance")
                module_info.append(appliance_status)
                module_info.append(computer.anti_malware.module_status.appliance_status_message)
        
                # Add the module info to the CSV string
                csv_line = ""
                for num, item in enumerate(module_info):
                    csv_line += item
                    if num != (len(module_info) - 1):
                        csv_line += ","
                    else:
                        csv_line += "\r\n"
                csv += csv_line

        return csv

    except api_exception as e:
        return "Exception: " + str(e)
