package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.grant.AdditionalGrantTypes;
import com.connellboyce.authhub.grant.TokenExchangeAuthenticationProvider;
import com.connellboyce.authhub.grant.TokenExchangeAuthenticationProvider.TokenExchangeException;
import com.connellboyce.authhub.grant.TokenExchangeAuthenticationProvider.TokenExchangeResult;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;

/**
 * OAuth 2.0 Token Endpoint Controller.
 * Handles token exchange (RFC 8693) and other OAuth 2.0 grant types.
 */
@Path("/oauth2")
@Produces(MediaType.APPLICATION_JSON)
public class OAuth2TokenController {
	
	@Inject
	TokenExchangeAuthenticationProvider tokenExchangeProvider;
	
	/**
	 * OAuth 2.0 Token Endpoint.
	 * Currently supports the token-exchange grant type (RFC 8693).
	 */
	@POST
	@Path("/token")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response token(
			@FormParam("grant_type") String grantType,
			@FormParam("client_id") String clientId,
			@FormParam("client_secret") String clientSecret,
			@FormParam("subject_token") String subjectToken,
			@FormParam("subject_token_type") String subjectTokenType,
			@FormParam("requested_token_type") String requestedTokenType,
			@FormParam("scope") String scope,
			@FormParam("actor_token") String actorToken,
			@FormParam("actor_token_type") String actorTokenType) {
		
		if (grantType == null || grantType.isEmpty()) {
			return errorResponse("invalid_request", "grant_type is required", null, Response.Status.BAD_REQUEST);
		}
		
		// Handle token exchange grant type
		if (AdditionalGrantTypes.TOKEN_EXCHANGE.equals(grantType)) {
			return handleTokenExchange(clientId, clientSecret, subjectToken, subjectTokenType, 
					requestedTokenType, scope, actorToken, actorTokenType);
		}
		
		// Other grant types not yet implemented in Quarkus
		return errorResponse("unsupported_grant_type", 
				"Grant type '" + grantType + "' is not supported",
				null, Response.Status.BAD_REQUEST);
	}
	
	private Response handleTokenExchange(
			String clientId,
			String clientSecret,
			String subjectToken,
			String subjectTokenType,
			String requestedTokenType,
			String scope,
			String actorToken,
			String actorTokenType) {
		
		try {
			TokenExchangeResult result = tokenExchangeProvider.exchange(
					clientId, clientSecret, subjectToken, subjectTokenType,
					requestedTokenType, scope, actorToken, actorTokenType);
			
			Map<String, Object> response = new HashMap<>();
			response.put("access_token", result.accessToken());
			response.put("token_type", result.tokenType());
			response.put("expires_in", result.expiresIn());
			if (result.scope() != null && !result.scope().isEmpty()) {
				response.put("scope", result.scope());
			}
			response.put("issued_token_type", result.issuedTokenType());
			
			return Response.ok(response).build();
			
		} catch (TokenExchangeException e) {
			Response.Status status = getStatusForError(e.getError());
			return errorResponse(e.getError(), e.getErrorDescription(), e.getErrorUri(), status);
		}
	}
	
	private Response errorResponse(String error, String description, String uri, Response.Status status) {
		Map<String, String> response = new HashMap<>();
		response.put("error", error);
		if (description != null) {
			response.put("error_description", description);
		}
		if (uri != null) {
			response.put("error_uri", uri);
		}
		return Response.status(status).entity(response).build();
	}
	
	private Response.Status getStatusForError(String error) {
		return switch (error) {
			case "invalid_client", "unauthorized_client" -> Response.Status.UNAUTHORIZED;
			case "invalid_grant", "invalid_request", "invalid_scope", 
					"unsupported_grant_type", "unsupported_token_type" -> Response.Status.BAD_REQUEST;
			case "server_error" -> Response.Status.INTERNAL_SERVER_ERROR;
			default -> Response.Status.BAD_REQUEST;
		};
	}
}
