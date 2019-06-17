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


def configure_max_sessions(api, configuration, api_version, api_exception, max_allowed, action):
    """ Configures the maximum number of active sessions allowed for users, and the action to take when the maximum is exceeded.
    Demonstrates how to configure multiple system properties.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param max_allowed: The number of maximum sessions allowed.
    :param action: The action to take when the max sessions is exceeded. Valid values are "Block new sessions" and "Expire oldest session".
    :return: A SettingValue object that contains the ID of the updated system settings.
    """

    # Create the SettingValue object and set the max sessions value
    max_sessions = api.SettingValue()
    max_sessions.value = str(max_allowed)

    # Add the SettingValue object to a SystemSettings object
    system_settings = api.SystemSettings()
    system_settings.platform_setting_active_sessions_max_num = max_sessions

    # Repeat for the platform_setting_active_sessions_max_exceeded_action
    exceed_action = api.SettingValue()
    exceed_action.value = action
    system_settings.platform_setting_active_sessions_max_exceeded_action = exceed_action

    try:
        # Modify system settings on Deep Security Manager
        settings_api = api.SystemSettingsApi(api.ApiClient(configuration))
        return settings_api.modify_system_settings(system_settings, api_version)

    except api_exception as e:
        return "Exception: " + str(e)


def set_allow_agent_initiated_activation(api, configuration, api_version, api_exception, allow):
    """ Configures whether agent-initiated activation is allowed. Demonstrates how to set a single system property.
    
    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param allow: The value for the system setting.
    :return: A SettingValue object that contains the value of the updated setting.
    """

    # Create the setting value
    allow_value = api.SettingValue()
    allow_value.value = str(allow)

    try:
        # Modify system setting on Deep Security Manager
        system_settings_api = api.SystemSettingsApi(api.ApiClient(configuration))
        return system_settings_api.modify_system_setting(api.SystemSettings.platform_setting_agent_initiated_activation_enabled, allow_value, api_version)

    except api_exception as e:
        return "Exception: " + str(e)


def add_computer (api, configuration, api_version, api_exception, hostname):
    """ Adds a computer to Deep Security Manager.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param hostname: The hostname or IP address that resolves to the computer.
    :return: An Integer that contains the ID of the computer.
    """

    # Create the computer object
    computer = api.Computer()
    computer.host_name = hostname

    try:
        # Add the computer to Deep Security Manager
        computers_api = api.ComputersApi(api.ApiClient(configuration))
        new_computer = computers_api.create_computer(computer, api_version)
        return new_computer.id

    except api_exception as e:
        return "Exception: " + str(e)

def get_agent_deployment_script (api, configuration, api_version, api_exception, platform, dsm_proxy_id = None, validate_certificate = None, activate = None, computer_group_id = None, policy_id = None, relay_id = None, relay_proxy_id = None):
    """ Obtains an agent deployment script from Deep Security Manager according to the provided parameter values

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param platform: The platform of the target computer. Valid values are linux, solaris, and windows.
    :param dsm_proxy_id: The ID of the proxy to use to connect to Deep Security Manager. Default is to use no proxy.
    :param validate_certificate: True indicates to validate that Deep Security Manager is using a valid TLS certificate from a trusted certificate authority (CA) when downloading the agent installer. Default is False.
    :param activate: True causes the script to activate the agent. Default is False.
    :param computer_group_id: The ID of the computer group to which the computer is added. Default is no group.
    :param policy_id: The ID of the policy to assign to the computer. Default is to assign no policy.
    :param relay_id: The ID of the relay to assign to the computer for obtaining updates. Default is no relay.
    :param relay_proxy_id: The ID of the proxy that the agent uses to connect to the relay. Default is to use no proxy.
    :return: A String that contains the deployment script.
    """

    # Create the AgentDeploymentScript object and configure
    deployment_script = api.AgentDeploymentScript()
    deployment_script.platform = platform
    deployment_script.dsm_proxy_id = dsm_proxy_id
    deployment_script.validate_certificate_required = validate_certificate
    deployment_script.activation_required = activate
    deployment_script.computer_group_id = computer_group_id
    deployment_script.policy_id = policy_id
    deployment_script.relay_id = relay_id
    deployment_script.replay_proxy_id = relay_proxy_id

    try:
        deployment_scripts_api = api.AgentDeploymentScriptsApi(api.ApiClient(configuration))
        deployment_script = deployment_scripts_api.generate_agent_deployment_script(api_version, agent_deployment_script = deployment_script)
        return deployment_script.script_body

    except api_exception as e:
        return "Exception: " + str(e)


