package com.connellboyce.authhub.service;

import com.connellboyce.authhub.model.dao.MongoRegisteredClient;
import com.connellboyce.authhub.model.payload.request.CreateClientRequest.ClientRegistration;
import io.quarkus.security.identity.SecurityIdentity;

import java.util.List;

public interface ClientService {
	MongoRegisteredClient createClient(ClientRegistration clientRegistration, String ownerId);
	List<MongoRegisteredClient> getClientsByOwner(String ownerId);
	MongoRegisteredClient getClientByClientId(String clientId);
	void deleteByClientId(String clientId);
	MongoRegisteredClient updateClient(String clientId, List<String> grantTypes, List<String> redirectUris, List<String> scopes) throws Exception;
	boolean validateClientOwnership(SecurityIdentity identity, String clientId);
}
