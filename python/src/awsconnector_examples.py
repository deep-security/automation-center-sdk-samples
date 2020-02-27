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


def create_aws_connector_using_access_keys(api, configuration, api_version, api_exception, display_name, access_key,
                                           secret_key, workspaces_enabled):
    """Creates an AWS Connector using the provided credentials.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param display_name: The name to display for this connector in Deep Security.
    :param access_key: AWS Access Key used to access this account.
    :param secret_key: AWS Secret Key used to access this account.
    :param workspaces_enabled: Whether WorkSpace computers should be synchronized with this account
    :return: An AWSConnectorsApi object that contains the ID of the created AWS Connector and its details.
    """

    aws_connectors_api = api.AWSConnectorsApi(api.ApiClient(configuration))
    aws_connector = api.AWSConnector()

    # Set the AWS Connector Properties
    aws_connector.display_name = display_name
    aws_connector.access_key = access_key
    aws_connector.secret_key = secret_key
    aws_connector.workspaces_enabled = workspaces_enabled

    api_response = aws_connectors_api.create_aws_connector(aws_connector, api_version)
    return api_response


def create_aws_connector_using_cross_account_role(api, configuration, api_version, api_exception, display_name,
                                                  cross_account_role_arn, workspaces_enabled):
    """Creates an AWS Connector using the provided credentials.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param display_name: The name to display for this connector in Deep Security.
    :param cross_account_role_arn: The role from this AWS Account that DSM will assume to authenticate this connector.
    :param workspaces_enabled: Whether WorkSpace computers should be synchronized with this account
    :return: An AWSConnectorsApi object that contains the ID of the created AWS Connector and its details.
    """

    aws_connectors_api = api.AWSConnectorsApi(api.ApiClient(configuration))
    aws_connector = api.AWSConnector()

    # Set the AWS Connector Properties
    aws_connector.display_name = display_name
    aws_connector.cross_account_role_arn = cross_account_role_arn
    aws_connector.workspaces_enabled = workspaces_enabled

    api_response = aws_connectors_api.create_aws_connector(aws_connector, api_version)
    return api_response


def create_aws_connector_using_instance_role(api, configuration, api_version, api_exception, display_name, workspaces_enabled):
    """Creates an AWS Connector using the provided credentials.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param display_name: The name to display for this connector in Deep Security.
    :param use_instance_role: Set to True to authenticate the account using Deep Security's instance role.
    :param workspaces_enabled: Whether WorkSpace computers should be synchronized with this account
    :return: An AWSConnectorsApi object that contains the ID of the created AWS Connector and its details.
    """

    aws_connectors_api = api.AWSConnectorsApi(api.ApiClient(configuration))
    aws_connector = api.AWSConnector()

    # Set the AWS Connector Properties
    aws_connector.display_name = display_name
    aws_connector.use_instance_role = True
    aws_connector.workspaces_enabled = workspaces_enabled

    api_response = aws_connectors_api.create_aws_connector(aws_connector, api_version)
    return api_response
