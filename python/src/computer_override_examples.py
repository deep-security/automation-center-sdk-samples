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


def override_reconnaissance_scan(api, configuration, api_version, api_exception, computer_id):
    """ Overrides a computer to enable Firewall reconnaissance scan.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param computer_id: The ID of the computer to override.
    :return: A Computer object that contains only overrides.
    """

    # Set the value for firewall_setting_reconnaissance_enabled
    setting_value = api.SettingValue()
    setting_value.value = "true"

    try:
        # Apply the override to the computer
        computers_api = api.ComputersApi(api.ApiClient(configuration))

        return computers_api.modify_computer_setting(computer_id, api.ComputerSettings.firewall_setting_reconnaissance_enabled, setting_value, api_version, overrides=True)

    except api_exception as e:
        return "Exception: " + str(e)


def get_computer_overrides(api, configuration, api_version, api_exception, computer_id, expand):
    """ Gets a Computer object that contains only overrides.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param computer_id: The ID of the computer.
    :param expand: The information to include in the returned Computer object
    :return: A Computer object that contains only overrides.
    """

    try:
        #
        # Get the Computer object with overrides set to True
        computers_api = api.ComputersApi(api.ApiClient(configuration))

        return computers_api.describe_computer(computer_id, api_version, expand=expand.list(), overrides=True)

    except api_exception as e:
        return "Exception: " + str(e)
