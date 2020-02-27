/*
 * Copyright 2020 Trend Micro.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Create an AWS connector using access keys.
 * @param {ApiClient} api           The Deep Security API exports.
 * @param {String} displayName      The display name of the AWS connector.
 * @param {String} accessKey        The AWS access key used to connect to the AWS connector.
 * @param {String} secretKey        The AWS secret key used to connect to the AWS connector.
 * @param {String} apiVersion       The API version to use.
 * @returns {Promise}               The promise contains the AWS connector object.
 */
exports.createAWSConnectorUsingAccessKey = function(api, displayName, accessKey, secretKey, apiVersion){
    let apiInstance = new api.AWSConnectorsApi();
    let AWSConnector = new api.AWSConnector();
    // Set the AWS connector properties.
    AWSConnector.displayName = displayName;
    AWSConnector.accessKey = accessKey;
    AWSConnector.secretKey = secretKey;
    return apiInstance.createAWSConnector(AWSConnector, apiVersion);
}

/**
 * Create an AWS connector using a cross-account role.
 * @param {ApiClient} api           The Deep Security API exports.
 * @param {String} displayName      The display name of the AWS connector.
 * @param {String} crossAccountRoleArn        The AWS cross account role ARN used to connect to the AWS connector.
 * @param {String} apiVersion       The API version to use.
 * @returns {Promise}               The promise contains the AWS connector object.
 */
exports.createAWSConnectorUsingCrossAccountRole = function(api, displayName, crossAccountRoleArn, apiVersion){
    let apiInstance = new api.AWSConnectorsApi();
    let AWSConnector = new api.AWSConnector();
    // Set the AWS connector properties.
    AWSConnector.displayName = displayName;
    AWSConnector.crossAccountRoleArn = crossAccountRoleArn;
    return apiInstance.createAWSConnector(AWSConnector, apiVersion);
}

/**
 * Create an AWS connector using the manager instance role.
 * @param {ApiClient} api           The Deep Security API exports.
 * @param {String} displayName      The display name of the AWS connector.
 * @param {String} apiVersion       The API version to use.
 * @returns {Promise}               The promise contains the AWS connector object.
 */
exports.createAWSConnectorUsingInstanceRole = function(api, displayName, apiVersion){
    let apiInstance = new api.AWSConnectorsApi();
    let AWSConnector = new api.AWSConnector();
    // Set the AWS connector properties.
    AWSConnector.displayName = displayName;
    AWSConnector.useInstanceRole = true;
    return apiInstance.createAWSConnector(AWSConnector, apiVersion);
}