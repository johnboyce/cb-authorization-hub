package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.model.dao.Scope;
import com.connellboyce.authhub.service.ApplicationService;
import com.connellboyce.authhub.service.ScopeService;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.net.URI;

@Path("/portal/operation/scope")
@RolesAllowed("DEVELOPER")
public class ScopesController {
	
	@Inject
	ScopeService scopeService;

	@Inject
	ApplicationService applicationService;

	@Inject
	SecurityIdentity identity;

	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response createScope(
			@FormParam("name") String name,
			@FormParam("applicationId") String applicationId) {
		
		// Validate ownership
		if (!applicationService.validateApplicationOwnership(identity, applicationId)) {
			return Response.status(Response.Status.FORBIDDEN).build();
		}
		
		try {
			Scope result = scopeService.createScope(name, applicationId);
			if (result != null) {
				return Response.seeOther(URI.create("/portal/applications/" + applicationId + "?success=Scope+created+successfully")).build();
			} else {
				return Response.seeOther(URI.create("/portal/applications/" + applicationId + "?error=Scope+creation+failed")).build();
			}
		} catch (Exception e) {
			return Response.seeOther(URI.create("/portal/applications/" + applicationId + "?error=Scope+creation+failed")).build();
		}
	}
}
