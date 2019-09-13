// Copyright (C) 2019 Trend Micro Inc. All rights reserved.

package com.trendmicro.deepsecurity.docs;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.GcpConnectorActionsApi;
import com.trendmicro.deepsecurity.api.GcpConnectorsApi;
import com.trendmicro.deepsecurity.model.Action;
import com.trendmicro.deepsecurity.model.GCPConnector;

/**
 * Examples of the GCP connector. 
 */
public class GcpConnectorExample {

	/**
	 * Create a GCP connector.
	 * 
	 * @param name           	The name of the GCP connector.
	 * @param serviceAccount 	The base64 string of the GCP service account.
	 * @param apiVersion     	The version of the API to use.
	 * @return 			Return the GCP connector object.
	 * @throws ApiException 	Throw an exception if a problem occurs when creating a GCP connector on
	 *                      	Deep Security Manager.
	 */
	public static GCPConnector createGcpConnector(String name, String serviceAccount, String apiVersion)
			throws ApiException {

		GcpConnectorsApi apiInstance = new GcpConnectorsApi();

		// Create a GCP connector.
		GCPConnector gcpConnector = new GCPConnector();
		gcpConnector.setName(name);
		gcpConnector.setServiceAccount(serviceAccount);

		// Add a GCP connector to Deep Security Manager.
		GCPConnector result = null;
		result = apiInstance.createGCPConnector(gcpConnector, apiVersion);

		return result;
	}

	/**
	 * Submit a sync action to the GCP connector.
	 * @param gcpConnectorID 	The target gcpConnectorID .
	 * @param apiVersion 		The version of the API to use.
	 * @return 			Return the action object which contains the action status.
	 * @throws ApiException 	Throw an exception if a problem occurs when creating a GCP connector on
	 *                      	Deep Security Manager.
	 */
	public static Action submitGCPConnectorSyncAction(Integer gcpConnectorID, String apiVersion) throws ApiException {
		
		GcpConnectorActionsApi apiInstance = new GcpConnectorActionsApi();
		//Set up the synchronize action.
		Action gcpConnectorAction = new Action();
		gcpConnectorAction.setType("synchronize");
		Action result = apiInstance.createGCPConnectorAction(gcpConnectorID, gcpConnectorAction, apiVersion);
		return result;
	}

}