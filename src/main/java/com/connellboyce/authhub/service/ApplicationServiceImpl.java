package com.connellboyce.authhub.service;

import com.connellboyce.authhub.model.dao.Application;
import com.connellboyce.authhub.model.dao.CBUser;
import com.connellboyce.authhub.repository.ApplicationRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.UUID;

@ApplicationScoped
@Named("applicationService")
public class ApplicationServiceImpl implements ApplicationService {

	@Inject
	ApplicationRepository applicationRepository;

	@Inject
	UserService userService;

	@Override
	@Transactional
	public Application createApplication(String name, String description, String ownerId) throws IllegalArgumentException {
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Application name is required");
		}
		if (description == null || description.isEmpty()) {
			throw new IllegalArgumentException("Application name is required");
		}
		if (applicationRepository.findByName(name).isPresent()) {
			throw new IllegalArgumentException("Application name " + name + " already exists");
		}
		if (ownerId == null || ownerId.isEmpty()) {
			throw new IllegalArgumentException("Owner ID is required");
		}
		Application app = new Application(String.valueOf(UUID.randomUUID()), name, description, ownerId);
		applicationRepository.persist(app);
		return app;
	}

	@Override
	public Application getApplicationById(String id) {
		return applicationRepository.findByIdString(id).orElse(null);
	}

	@Override
	public List<Application> getApplicationsByOwnerId(String ownerId) {
		return applicationRepository.findByOwnerId(ownerId).orElse(null);
	}

	@Override
	@Transactional
	public Application updateApplication(String id, String name, String description, String ownerId) {
		//TODO validate inputs
		//TODO ensure no duplicate names
		Application app = new Application(id, name, description, ownerId);
		applicationRepository.persist(app);
		return app;
	}

	@Override
	@Transactional
	public void deleteApplicationById(String id) {
		applicationRepository.deleteApplicationById(id);
	}

	@Override
	public boolean validateApplicationOwnership(SecurityIdentity identity, String applicationId) {
		if (identity == null || applicationId == null || applicationId.isEmpty()) {
			return false;
		}
		CBUser user = userService.getCBUserByUsername(identity.getPrincipal().getName());
		Application application = getApplicationById(applicationId);
		if (application == null || user == null) {
			return false;
		}
		if (application.getOwnerId() == null || application.getOwnerId().isEmpty()) {
			return false;
		}

		return application.getOwnerId().equals(user.getId());
	}
}
