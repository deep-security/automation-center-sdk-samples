# Copyright 2020 Trend Micro.
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

def create_xdr_registration(api, configuration, api_version, api_exception, registration_token):
    """ Register XDR Service with the enrollment token.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param registration_token: The enrollment token from XDR console.
    :return: An Integer that contains the ID of the registry scanner.
    """

    # Create the registry scanner object
    xdr_registration = api.XdrRegistration(registration_token)

    # Add the registry scanner to Deep Security Manager
    xdr_registration_api = api.XDRRegistrationApi(api.ApiClient(configuration))
    api_response = xdr_registration_api.create_xdr_registration(xdr_registration, api_version)
    return api_response.id
