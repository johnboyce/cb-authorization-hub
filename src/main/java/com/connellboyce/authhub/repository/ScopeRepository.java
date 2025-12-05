package com.connellboyce.authhub.repository;

import com.connellboyce.authhub.model.dao.Scope;
import io.quarkus.mongodb.panache.PanacheMongoRepository;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class ScopeRepository implements PanacheMongoRepository<Scope> {
	
	public Optional<Scope> findByName(String name) {
		return find("name", name).firstResultOptional();
	}
	
	public Optional<List<Scope>> findByApplicationId(String applicationId) {
		List<Scope> scopes = find("applicationId", applicationId).list();
		return scopes.isEmpty() ? Optional.empty() : Optional.of(scopes);
	}
}
