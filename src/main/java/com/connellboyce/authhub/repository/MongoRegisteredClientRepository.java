package com.connellboyce.authhub.repository;

import com.connellboyce.authhub.model.dao.MongoRegisteredClient;
import io.quarkus.mongodb.panache.PanacheMongoRepository;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class MongoRegisteredClientRepository implements PanacheMongoRepository<MongoRegisteredClient> {
	
	public Optional<MongoRegisteredClient> findByClientId(String clientId) {
		return find("clientId", clientId).firstResultOptional();
	}
	
	public Optional<List<MongoRegisteredClient>> findByOwnerId(String ownerId) {
		List<MongoRegisteredClient> clients = find("ownerId", ownerId).list();
		return clients.isEmpty() ? Optional.empty() : Optional.of(clients);
	}
	
	public void deleteByClientId(String clientId) {
		delete("clientId", clientId);
	}
}
