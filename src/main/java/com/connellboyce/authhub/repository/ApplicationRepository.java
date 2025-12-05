package com.connellboyce.authhub.repository;

import com.connellboyce.authhub.model.dao.Application;
import io.quarkus.mongodb.panache.PanacheMongoRepository;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class ApplicationRepository implements PanacheMongoRepository<Application> {
	
	public Optional<Application> findByIdString(String id) {
		return find("_id", id).firstResultOptional();
	}
	
	public Optional<Application> findByName(String name) {
		return find("name", name).firstResultOptional();
	}
	
	public Optional<List<Application>> findByOwnerId(String ownerId) {
		List<Application> apps = find("ownerId", ownerId).list();
		return apps.isEmpty() ? Optional.empty() : Optional.of(apps);
	}
	
	public void deleteApplicationById(String id) {
		delete("_id", id);
	}
}
