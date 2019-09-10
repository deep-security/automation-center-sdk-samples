// Copyright (C) 2019 Trend Micro Inc. All rights reserved.

package com.trendmicro.deepsecurity.docs;

import com.trendmicro.deepsecurity.ApiException;
import com.trendmicro.deepsecurity.api.GcpConnectorActionsApi;
import com.trendmicro.deepsecurity.api.GcpConnectorsApi;
import com.trendmicro.deepsecurity.model.Action;
import com.trendmicro.deepsecurity.model.GCPConnector;

/**
 * the examples of gcp connector 
 */
public class GcpConnectorExample {

	/**
	 * create a gcp connector
	 * 
	 * @param name           the name of the gcp connector
	 * @param serviceAccount the base64 string of the gcp service account
	 * @param apiVersion     The version of the API to use.
	 * @return the GCPConnector object
	 * @throws ApiException if a problem occurs when creating a gcp connector on
	 *                      Deep Security Manager.
	 */
	public static GCPConnector createGcpConnector(String name, String serviceAccount, String apiVersion)
			throws ApiException {

		GcpConnectorsApi apiInstance = new GcpConnectorsApi();

		// Create a GCPConnector
		GCPConnector gcpConnector = new GCPConnector();
		gcpConnector.setName(name);
		gcpConnector.setServiceAccount(serviceAccount);

		// Add a GcpConnector to Deep Security Manager
		GCPConnector result = null;
		result = apiInstance.createGCPConnector(gcpConnector, apiVersion);

		return result;
	}

	/**
	 * submit a sync action to the gcp connector
	 * @param gcpConnectorID the target gcpConnectorID 
	 * @param apiVersion The version of the API to use.
	 * @return the action object which contains the action status.
	 * @throws ApiException if a problem occurs when creating a gcp connector on
	 *                      Deep Security Manager.
	 */
	public static Action submitGCPConnectorSyncAction(Integer gcpConnectorID, String apiVersion) throws ApiException {
		
		GcpConnectorActionsApi apiInstance = new GcpConnectorActionsApi();
		//setup synchronize action
		Action gcpConnectorAction = new Action();
		gcpConnectorAction.setType("synchronize");
		Action result = apiInstance.createGCPConnectorAction(gcpConnectorID, gcpConnectorAction, apiVersion);
		return result;
	}

}