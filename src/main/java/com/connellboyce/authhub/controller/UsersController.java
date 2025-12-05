package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.model.dao.CBUser;
import com.connellboyce.authhub.model.payload.request.CreateUserRequest;
import com.connellboyce.authhub.service.UserService;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/api/v1/user")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UsersController {
	
	@Inject
	UserService userService;

	@POST
	public Response createUser(CreateUserRequest createUserRequest) {
		try {
			CBUser result = userService.createUser(
					createUserRequest.getUsername(),
					createUserRequest.getPassword(),
					createUserRequest.getEmail(),
					createUserRequest.getFirstName(),
					createUserRequest.getLastName()
			);

			return result == null 
					? Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("User creation failed").build() 
					: Response.ok(result).build();
		} catch (IllegalArgumentException e) {
			return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
		}
	}
}
