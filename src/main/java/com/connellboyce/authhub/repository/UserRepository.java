package com.connellboyce.authhub.repository;

import com.connellboyce.authhub.model.dao.CBUser;
import io.quarkus.mongodb.panache.PanacheMongoRepository;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Optional;

@ApplicationScoped
public class UserRepository implements PanacheMongoRepository<CBUser> {
	
	public Optional<CBUser> findByIdString(String id) {
		return find("_id", id).firstResultOptional();
	}
	
	public Optional<CBUser> findByUsername(String username) {
		return find("username", username).firstResultOptional();
	}
	
	public Optional<CBUser> findByEmail(String email) {
		return find("email", email).firstResultOptional();
	}
}
