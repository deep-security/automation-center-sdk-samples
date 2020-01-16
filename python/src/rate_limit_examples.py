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

def set_computer_policy_check_rate_limit(api, configuration, api_version, api_exception, computer_ids, policy_id):
    """ Sets the policy for a number of computers. On each call to Deep Security Manager, checks whether the API rate limits are exceeded and if so retries the call.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param computer_ids: A list of IDs of the computers to modify.
    :param policy_id: The ID of the policy to assign.
    :return: A PoliciesApi object that contains the ID of the modified policy.
    """

    import time

    computers_api = api.ComputersApi(api.ApiClient(configuration))

    # IDs of modified computers
    modified_computer_ids = []

    # Count the number of computers that have been modified -- also used as the index for computer_ids
    change_count = 0

    # Count retries, and set a maximum
    retries = 0
    MAX_RETRIES = 12

    while True:

        # Create a computer object and set the policy ID
        computer = api.Computer()
        computer.policy_id = policy_id
        try:
            # Modify the computer on Deep Security Manager and store the ID of the returned computer
            computer = computers_api.modify_computer(computer_ids[change_count], computer, api_version, overrides=False)
            modified_computer_ids.append(computer.id)
            retries = 0

            # Increment the count and return if all computers are modified
            change_count += 1
            if change_count == len(computer_ids):
                return modified_computer_ids
        except api_exception as e:
            if e.status == 429 and retries < MAX_RETRIES:
                # The error is due to exceeding an API rate limit
                retries += 1

                # Calculate sleep time
                exp_backoff = (2 ** (retries +3)) / 1000
                print("API rate limit is exceeded. Retry in {} s.".format(exp_backoff))
                time.sleep(exp_backoff)
            else:
                # Return all other exception causes or when max retries is exceeded
                return e