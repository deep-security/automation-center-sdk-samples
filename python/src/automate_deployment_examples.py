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


def configure_system_settings(api, configuration, api_version, api_exception):
    """ Configures the maximum number of active sessions. Demonstrates how to
    configure system properties.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A SystemSettingsApi object that contains the ID of the updated system settings.
    """

    # Create the SettingValue object and set the max sessions value
    max_sessions = api.SettingValue()
    max_sessions.value = "100"

    # Add the SettingValue object to a SystemSettings object
    system_settings = api.SystemSettings()
    system_settings.platform_setting_active_sessions_max_num = max_sessions

    try:
        # Modify system settings on Deep Security Manager
        settings_api = api.SystemSettingsApi(api.ApiClient(configuration))
        return settings_api.modify_system_settings(system_settings, api_version)

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
