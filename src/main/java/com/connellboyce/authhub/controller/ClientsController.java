package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.model.dao.MongoRegisteredClient;
import com.connellboyce.authhub.service.AuthUtilService;
import com.connellboyce.authhub.service.ClientService;
import io.quarkus.logging.Log;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static com.connellboyce.authhub.model.payload.request.CreateClientRequest.toClientRegistration;

@Path("/portal/operation/client")
@RolesAllowed("DEVELOPER")
public class ClientsController {

	@Inject
	ClientService clientService;

	@Inject
	AuthUtilService authUtilService;

	@Inject
	SecurityIdentity identity;

	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response createClient(
			@FormParam("clientId") String clientId,
			@FormParam("clientSecret") String clientSecret,
			@FormParam("grantTypes") List<String> grantTypes,
			@FormParam("redirectUrls") List<String> redirectUrls,
			@FormParam("scopes") List<String> scopes) {
		
		Optional<String> userId = authUtilService.getUserIdFromSecurityIdentity(identity);
		if (userId.isEmpty()) {
			return Response.seeOther(URI.create("/portal/clients?error=User+not+authenticated")).build();
		}

		var clientRegistration = toClientRegistration(clientId, clientSecret, redirectUrls, scopes, grantTypes);

		Log.debugf("Creating client with ID: %s", clientId);
		MongoRegisteredClient client = clientService.createClient(clientRegistration, userId.get());
		if (client != null) {
			return Response.seeOther(URI.create("/portal/clients?success=Client+created+successfully")).build();
		} else {
			return Response.seeOther(URI.create("/portal/clients?error=Failed+to+create+client")).build();
		}
	}

	@PUT
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response updateClient(
			@FormParam("clientId") String clientId,
			@FormParam("grantTypes") List<String> grantTypes,
			@FormParam("redirectUrls") List<String> redirectUrls,
			@FormParam("scopes") List<String> scopes) {
		
		// Validate ownership
		if (!clientService.validateClientOwnership(identity, clientId)) {
			return Response.status(Response.Status.FORBIDDEN).build();
		}
		
		Optional<String> userId = authUtilService.getUserIdFromSecurityIdentity(identity);
		if (userId.isEmpty()) {
			return Response.seeOther(URI.create("/portal/clients?error=User+not+authenticated")).build();
		}

		try {
			clientService.updateClient(clientId, grantTypes, redirectUrls, scopes);
			return Response.seeOther(URI.create("/portal/clients?success=Client+updated+successfully")).build();
		} catch (Exception e) {
			Log.errorf("Error updating client: %s", e.getMessage());
			return Response.seeOther(URI.create("/portal/clients?error=Failed+to+update+client")).build();
		}
	}

	@DELETE
	@Path("/{clientId}")
	public Response deleteClient(@PathParam("clientId") String clientId) {
		// Validate ownership
		if (!clientService.validateClientOwnership(identity, clientId)) {
			return Response.status(Response.Status.FORBIDDEN).build();
		}
		
		clientService.deleteByClientId(clientId);
		return Response.seeOther(URI.create("/portal/clients?success=Client+deleted+successfully")).build();
	}
}
