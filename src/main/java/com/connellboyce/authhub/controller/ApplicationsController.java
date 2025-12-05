package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.model.dao.Application;
import com.connellboyce.authhub.service.ApplicationService;
import com.connellboyce.authhub.service.AuthUtilService;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.net.URI;
import java.util.Optional;

@Path("/portal/operation/application")
@RolesAllowed("DEVELOPER")
public class ApplicationsController {
	
	@Inject
	ApplicationService applicationService;

	@Inject
	AuthUtilService authUtilService;

	@Inject
	SecurityIdentity identity;

	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response createApplication(
			@FormParam("applicationName") String name,
			@FormParam("description") String description) {
		
		Optional<String> userId = authUtilService.getUserIdFromSecurityIdentity(identity);
		if (userId.isEmpty()) {
			return Response.seeOther(URI.create("/portal/applications?error=User+not+authenticated")).build();
		}

		try {
			Application result = applicationService.createApplication(name, description, userId.get());
			if (result != null) {
				return Response.seeOther(URI.create("/portal/applications?success=Application+created+successfully")).build();
			} else {
				return Response.seeOther(URI.create("/portal/applications?error=Application+creation+failed")).build();
			}
		} catch (IllegalArgumentException e) {
			return Response.seeOther(URI.create("/portal/applications?error=Application+creation+failed")).build();
		}
	}

	@PUT
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response updateApplication(
			@FormParam("id") String id,
			@FormParam("applicationName") String name,
			@FormParam("description") String description) {
		
		// Validate ownership
		if (!applicationService.validateApplicationOwnership(identity, id)) {
			return Response.status(Response.Status.FORBIDDEN).build();
		}
		
		Optional<String> userId = authUtilService.getUserIdFromSecurityIdentity(identity);
		if (userId.isEmpty()) {
			return Response.seeOther(URI.create("/portal/applications/" + id + "?error=User+not+authenticated")).build();
		}

		Application result = applicationService.updateApplication(id, name, description, userId.get());
		if (result != null) {
			return Response.seeOther(URI.create("/portal/applications/" + id + "?success=Application+updated+successfully")).build();
		} else {
			return Response.seeOther(URI.create("/portal/applications/" + id + "?error=Application+update+failed")).build();
		}
	}

	@DELETE
	@Path("/{id}")
	public Response deleteApplication(@PathParam("id") String id) {
		// Validate ownership
		if (!applicationService.validateApplicationOwnership(identity, id)) {
			return Response.status(Response.Status.FORBIDDEN).build();
		}
		
		applicationService.deleteApplicationById(id);
		return Response.seeOther(URI.create("/portal/applications?success=Application+deleted+successfully")).build();
	}
}
