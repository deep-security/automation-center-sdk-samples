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

def add_registry_scanner(api, configuration, api_version, api_exception, name, url, user_account, user_password):
    """ Adds a registry scanner to Deep Security Manager.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param name: The name or IP address of the registry scanner.
    :param url: The url of the registry scanner.
    :param user_account: The user account that can login to the registry scanner.
    :param user_password: The password of the user.
    :return: An Integer that contains the ID of the registry scanner.
    """

    # Create the registry scanner object
    registry_scanner = api.RegistryScanner()
    registry_scanner.name = name
    registry_scanner.url = url
    registry_scanner.username = user_account
    registry_scanner.password = user_password

    try:
        # Add the registry scanner to Deep Security Manager
        registry_scanner_api = api.RegistryScannersApi(api.ApiClient(configuration))
        api_response = registry_scanner_api.create_registry_scanner(registry_scanner, api_version)
        return api_response.id

    except api_exception as e:
        return "Exception: " + str(e)
