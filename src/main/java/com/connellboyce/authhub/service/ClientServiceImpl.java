package com.connellboyce.authhub.service;

import com.connellboyce.authhub.model.dao.CBUser;
import com.connellboyce.authhub.model.dao.MongoRegisteredClient;
import com.connellboyce.authhub.model.payload.request.CreateClientRequest.ClientRegistration;
import com.connellboyce.authhub.repository.MongoRegisteredClientRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.transaction.Transactional;
import org.mindrot.jbcrypt.BCrypt;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@ApplicationScoped
@Named("clientService")
public class ClientServiceImpl implements ClientService {

	@Inject
	MongoRegisteredClientRepository repository;

	@Inject
	UserService userService;

	@Override
	@Transactional
	public MongoRegisteredClient createClient(ClientRegistration clientRegistration, String ownerId) {
		MongoRegisteredClient mongoClient = new MongoRegisteredClient();
		mongoClient.setId(clientRegistration.id());
		mongoClient.setClientId(clientRegistration.clientId());
		mongoClient.setClientSecret(BCrypt.hashpw(clientRegistration.clientSecret(), BCrypt.gensalt()));
		mongoClient.setClientAuthenticationMethods(Set.of("client_secret_basic", "client_secret_post"));
		mongoClient.setAuthorizationGrantTypes(new HashSet<>(clientRegistration.grantTypes()));
		mongoClient.setRedirectUris(new HashSet<>(clientRegistration.redirectUris()));
		mongoClient.setScopes(new HashSet<>(clientRegistration.scopes()));
		mongoClient.setRequireAuthorizationConsent(true);
		mongoClient.setOwnerId(ownerId);

		repository.persist(mongoClient);
		return mongoClient;
	}

	@Override
	public List<MongoRegisteredClient> getClientsByOwner(String ownerId) {
		return repository.findByOwnerId(ownerId).orElse(List.of());
	}

	@Override
	public MongoRegisteredClient getClientByClientId(String clientId) {
		return repository.findByClientId(clientId).orElse(null);
	}

	@Override
	@Transactional
	public void deleteByClientId(String clientId) {
		repository.deleteByClientId(clientId);
	}

	@Override
	@Transactional
	public MongoRegisteredClient updateClient(String clientId, List<String> grantTypes, List<String> redirectUris, List<String> scopes) throws Exception {
		MongoRegisteredClient client = repository.findByClientId(clientId).orElse(null);
		if (client == null) {
			throw new Exception("Client not found");
		}
		client.setAuthorizationGrantTypes(new HashSet<>(grantTypes));
		client.setRedirectUris(new HashSet<>(redirectUris));
		client.setScopes(new HashSet<>(scopes));
		repository.persist(client);
		return client;
	}

	@Override
	public boolean validateClientOwnership(SecurityIdentity identity, String clientId) {
		if (identity == null || clientId == null || clientId.isEmpty()) {
			return false;
		}
		CBUser user = userService.getCBUserByUsername(identity.getPrincipal().getName());
		MongoRegisteredClient client = getClientByClientId(clientId);
		if (client == null || user == null) {
			return false;
		}
		if (client.getOwnerId() == null || client.getOwnerId().isEmpty()) {
			return false;
		}
		if (user.getId() == null || user.getId().isEmpty()) {
			return false;
		}

		return client.getOwnerId().equals(user.getId());
	}
}
