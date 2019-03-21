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

def create_audit_key(api, configuration, api_version, api_exception, key_name):
    import time
    """ Creates an API key with read-only permissions that expires in 2 weeks.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param key_name: The name for the key.
    :return: An APIKeysApi object that contains the ID of the created API key.
    """

    # Set key properties
    time_to_expiry_in_ms = 14 * 24 * 60 * 60 * 1000
    current_time_in_ms = int(round(time.time() * 1000))

    key = api.ApiKey()
    key.key_name = key_name
    key.description = "Read-only access"
    key.role_id = "2"
    key.locale = "en-US"
    key.time_zone = "Asia/Tokyo"
    key.expiry_date = current_time_in_ms + time_to_expiry_in_ms # expires in 2 weeks

    try:
        # Create the key on Deep Security Manager
        api_keys_api = api.APIKeysApi(api.ApiClient(configuration))
        return api_keys_api.create_api_key(key, api_version)

    except api_exception as e:
        return "Exception: " + str(e)


def reset_key_secret(api, configuration, api_version, api_exception, key_id):
    """ Resets the secret of an API key.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param key_id: The ID of the key.
    :return: An APIKeysApi object that contains the secret of the key.
    """

    try:
        # Reset the key
        api_keys_api = api.APIKeysApi(api.ApiClient(configuration))
        return api_keys_api.replace_api_secret_key(key_id, api_version)

    except api_exception as e:
        return "Exception: " + str(e)


def modify_key_role(api, configuration, api_version, api_exception, key_id, role_id):
    """ Changes the role that an API key uses.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param key_id: The ID of the key.
    :param role_id: The ID of the role to use.
    :return: An APIKeysApi object that contains the ID of the role that the key uses.
    """

    # Create a key and set the role ID
    key = api.ApiKey()
    key.role_id = role_id

    try:
        # Modify the key on Deep Security Manager
        api_keys_api = api.APIKeysApi(api.ApiClient(configuration))
        api_keys_api.modify_api_key(key_id, key, api_version)
        return key.role_id

    except api_exception as e:
        return "Exception: " + str(e)
