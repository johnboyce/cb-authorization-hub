package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.model.dao.Scope;
import com.connellboyce.authhub.service.ApplicationService;
import com.connellboyce.authhub.service.ClientService;
import com.connellboyce.authhub.service.ScopeService;
import com.connellboyce.authhub.service.UserService;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public class PageController {

	@Inject
	Template login;

	@Inject
	Template register;

	@Inject
	Template portalIndex;

	@Inject
	Template portalClients;

	@Inject
	Template portalApplications;

	@Inject
	Template portalCreateApplication;

	@Inject
	Template portalCreateClient;

	@Inject
	Template portalEditApplication;

	@Inject
	Template portalEditClient;

	@Inject
	ClientService clientService;

	@Inject
	UserService userService;

	@Inject
	ApplicationService applicationService;

	@Inject
	ScopeService scopeService;

	@Inject
	SecurityIdentity identity;

	@GET
	@Path("/login")
	public TemplateInstance loginPage() {
		// For now, simplified without session management
		return login.data("client", null);
	}

	@GET
	@Path("/register")
	public TemplateInstance registerPage() {
		return register.instance();
	}

	@GET
	@Path("/portal/index")
	@RolesAllowed("DEVELOPER")
	public TemplateInstance portalHomePage() {
		return portalIndex.data("name", identity.getPrincipal().getName());
	}

	@GET
	@Path("/portal/clients")
	@RolesAllowed("DEVELOPER")
	public TemplateInstance portalClientsPage() {
		var user = userService.getCBUserByUsername(identity.getPrincipal().getName());
		var clients = clientService.getClientsByOwner(user.getId());
		return portalClients.data("clients", clients);
	}

	@GET
	@Path("/portal/applications")
	@RolesAllowed("DEVELOPER")
	public TemplateInstance portalApplicationsPage() {
		var user = userService.getCBUserByUsername(identity.getPrincipal().getName());
		var applications = applicationService.getApplicationsByOwnerId(user.getId());
		return portalApplications.data("applications", applications);
	}

	@GET
	@Path("/portal/applications/create")
	@RolesAllowed("DEVELOPER")
	public TemplateInstance createApplicationPage() {
		return portalCreateApplication.instance();
	}

	@GET
	@Path("/portal/clients/create")
	@RolesAllowed("DEVELOPER")
	public TemplateInstance createClientPage() {
		Map<String, String> grantTypes = Map.of(
				"authorization_code", "Authorization Code",
				"client_credentials", "Client Credentials",
				"refresh_token", "Refresh Token",
				"urn:ietf:params:oauth:grant-type:token-exchange", "Token Exchange"
		);
		
		Map<String, List<Scope>> scopeMap = new HashMap<>();
		scopeService.getAllScopes().forEach(scope -> {
			String appName = applicationService.getApplicationById(scope.getApplicationId()).getName();
			scopeMap.computeIfAbsent(appName, k -> new ArrayList<>()).add(scope);
		});
		
		return portalCreateClient
				.data("generatedSecret", generateSecret())
				.data("grantTypes", grantTypes)
				.data("scopesByApplication", scopeMap);
	}

	@GET
	@Path("/portal/applications/{id}")
	@RolesAllowed("DEVELOPER")
	public TemplateInstance editApplicationPage(@PathParam("id") String id) {
		//TODO: Check if the user is the owner of the application
		return portalEditApplication
				.data("app", applicationService.getApplicationById(id))
				.data("scopes", scopeService.getScopesByApplicationId(id));
	}

	@GET
	@Path("/portal/clients/{clientId}")
	@RolesAllowed("DEVELOPER")
	public TemplateInstance editClientPage(@PathParam("clientId") String clientId) {
		//TODO: Check if the user is the owner of the client
		Map<String, String> grantTypes = Map.of(
				"authorization_code", "Authorization Code",
				"client_credentials", "Client Credentials",
				"refresh_token", "Refresh Token",
				"urn:ietf:params:oauth:grant-type:token-exchange", "Token Exchange"
		);
		
		Map<String, List<Scope>> scopeMap = new HashMap<>();
		scopeService.getAllScopes().forEach(scope -> {
			String appName = applicationService.getApplicationById(scope.getApplicationId()).getName();
			scopeMap.computeIfAbsent(appName, k -> new ArrayList<>()).add(scope);
		});
		
		return portalEditClient
				.data("client", clientService.getClientByClientId(clientId))
				.data("grantTypes", grantTypes)
				.data("scopesByApplication", scopeMap);
	}

	private String generateSecret() {
		try {
			SecureRandom random = SecureRandom.getInstanceStrong();
			byte[] values = new byte[32];
			random.nextBytes(values);
			return Base64.getEncoder().encodeToString(values);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to generate secure random value:", e);
		}
	}
}
