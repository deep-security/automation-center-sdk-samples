/*
 * Copyright 2019 Trend Micro.
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
 * Create a GCP connector.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {String} name The name of gcpconnector.
 * @param {String} serviceAccount The service account of gcpconnector.
 * @param {String} apiVersion The api version to use.
 * @returns {Promise} A promise contains GCP Connector object.
 */
exports.createGcpConnector = function(api, name, serviceAccount, apiVersion){
    let apiInstance = new api.GCPConnectorsApi();
    let gcpConnector = new api.GCPConnector();
    // Set Gcp connector properties.
    gcpConnector.name = name;
    gcpConnector.serviceAccount = serviceAccount;
    return apiInstance.createGCPConnector(gcpConnector, apiVersion);
}

/**
 * Submit a synchronize action of a GCP connector by ID.
 * @param {ApiClient} api The Deep Security API exports.
 * @param {Number} gcpConnectorID The ID of the gcpconnector.
 * @returns {Promise} A promise contains GCP Connector object.
 */
exports.submitGcpConnectorAction = function(api, gcpConnectorID, apiVersion){
    let apiInstance = new api.GCPConnectorActionsApi();
    // Set Action
    let gcpConnectorAction = new api.Action();
    gcpConnectorAction.type = "synchronize";
    return apiInstance.createGCPConnectorAction(gcpConnectorID, gcpConnectorAction, apiVersion);
}
