package com.connellboyce.authhub.service;

import com.connellboyce.authhub.model.dao.Application;
import io.quarkus.security.identity.SecurityIdentity;

import java.util.List;

public interface ApplicationService {
	Application createApplication(String name, String description, String ownerId) throws IllegalArgumentException;
	Application getApplicationById(String id);
	List<Application> getApplicationsByOwnerId(String ownerId);
	Application updateApplication(String id, String name, String description, String ownerId);
	void deleteApplicationById(String id);
	boolean validateApplicationOwnership(SecurityIdentity identity, String applicationId);
}
