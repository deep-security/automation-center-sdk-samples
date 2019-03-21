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

import deepsecurity as api
from deepsecurity.rest import ApiException as api_exception


def get_policies_list(api, configuration, api_version, api_exception):
    """ Gets a list of policies on the Deep Security Manager

    :return: A PoliciesApi object that contains a list of policies.
    """

    try:
        # Create a PoliciesApi object
        policies_api = api.PoliciesApi(api.ApiClient(configuration))

        # List policies using version v1 of the API
        policies_list = policies_api.list_policies(api_version)

        # View the list of policies
        return policies_list

    except api_exception as e:
        return "Exception: " + str(e)

if __name__ == '__main__':
    # Add Deep Security Manager host information to the api client configuration
    configuration = api.Configuration()
    configuration.host = 'https://192.168.17.149:4119/api'

    # Authentication
    configuration.api_key['api-secret-key'] = '2:l069trAePqPRxZUfBqyw442z1DWm9s4u0F/g9bewnFE='

    # Version
    api_version = 'v1'
    print(get_policies_list(api, configuration, api_version, api_exception))