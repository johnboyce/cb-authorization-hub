package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.grant.AdditionalGrantTypes;
import com.connellboyce.authhub.oauth2.OAuth2Service;
import com.connellboyce.authhub.oauth2.OAuth2Service.OAuth2Exception;
import com.connellboyce.authhub.oauth2.OAuth2Service.TokenResponse;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;

/**
 * OAuth 2.0 Token Endpoint Controller.
 * Handles all OAuth 2.0 grant types including:
 * - authorization_code
 * - client_credentials
 * - refresh_token
 * - urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693)
 */
@Path("/oauth2")
@Produces(MediaType.APPLICATION_JSON)
public class OAuth2TokenController {
	
	@Inject
	OAuth2Service oauth2Service;
	
	/**
	 * OAuth 2.0 Token Endpoint.
	 */
	@POST
	@Path("/token")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response token(
			@FormParam("grant_type") String grantType,
			@FormParam("client_id") String clientId,
			@FormParam("client_secret") String clientSecret,
			@FormParam("code") String code,
			@FormParam("redirect_uri") String redirectUri,
			@FormParam("code_verifier") String codeVerifier,
			@FormParam("refresh_token") String refreshToken,
			@FormParam("subject_token") String subjectToken,
			@FormParam("subject_token_type") String subjectTokenType,
			@FormParam("requested_token_type") String requestedTokenType,
			@FormParam("scope") String scope,
			@FormParam("actor_token") String actorToken,
			@FormParam("actor_token_type") String actorTokenType) {
		
		if (grantType == null || grantType.isEmpty()) {
			return errorResponse("invalid_request", "grant_type is required", Response.Status.BAD_REQUEST);
		}
		
		try {
			TokenResponse result;
			if ("authorization_code".equals(grantType)) {
				result = oauth2Service.exchangeAuthorizationCode(clientId, clientSecret, code, redirectUri, codeVerifier);
			} else if ("client_credentials".equals(grantType)) {
				result = oauth2Service.clientCredentialsGrant(clientId, clientSecret, scope);
			} else if ("refresh_token".equals(grantType)) {
				result = oauth2Service.refreshTokenGrant(clientId, clientSecret, refreshToken, scope);
			} else if (AdditionalGrantTypes.TOKEN_EXCHANGE.equals(grantType)) {
				result = oauth2Service.tokenExchangeGrant(clientId, clientSecret, subjectToken, 
						subjectTokenType, requestedTokenType, scope);
			} else {
				throw new OAuth2Exception("unsupported_grant_type", 
						"Grant type '" + grantType + "' is not supported");
			}
			
			return buildTokenResponse(result);
			
		} catch (OAuth2Exception e) {
			Response.Status status = getStatusForError(e.getError());
			return errorResponse(e.getError(), e.getMessage(), status);
		}
	}
	
	/**
	 * OAuth 2.0 Introspection Endpoint (RFC 7662).
	 */
	@POST
	@Path("/introspect")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response introspect(
			@FormParam("token") String token,
			@FormParam("client_id") String clientId,
			@FormParam("client_secret") String clientSecret) {
		
		try {
			Map<String, Object> result = oauth2Service.introspectToken(token, clientId, clientSecret);
			return Response.ok(result).build();
		} catch (OAuth2Exception e) {
			Response.Status status = getStatusForError(e.getError());
			return errorResponse(e.getError(), e.getMessage(), status);
		}
	}
	
	/**
	 * JWKS Endpoint - Returns public keys for token verification.
	 */
	@GET
	@Path("/jwks")
	public Response jwks() {
		return Response.ok(oauth2Service.getJwks()).build();
	}
	
	/**
	 * OpenID Connect UserInfo Endpoint.
	 */
	@GET
	@Path("/userinfo")
	public Response userInfo(@HeaderParam("Authorization") String authorization) {
		if (authorization == null || !authorization.startsWith("Bearer ")) {
			return errorResponse("invalid_token", "Access token required", Response.Status.UNAUTHORIZED);
		}
		
		String accessToken = authorization.substring(7);
		
		try {
			Map<String, Object> result = oauth2Service.getUserInfo(accessToken);
			return Response.ok(result).build();
		} catch (OAuth2Exception e) {
			Response.Status status = getStatusForError(e.getError());
			return errorResponse(e.getError(), e.getMessage(), status);
		}
	}
	
	/**
	 * POST method for UserInfo (some clients prefer this).
	 */
	@POST
	@Path("/userinfo")
	public Response userInfoPost(@HeaderParam("Authorization") String authorization) {
		return userInfo(authorization);
	}
	
	private Response buildTokenResponse(TokenResponse result) {
		Map<String, Object> response = new HashMap<>();
		response.put("access_token", result.accessToken());
		response.put("token_type", result.tokenType());
		response.put("expires_in", result.expiresIn());
		
		if (result.refreshToken() != null) {
			response.put("refresh_token", result.refreshToken());
		}
		if (result.scope() != null && !result.scope().isEmpty()) {
			response.put("scope", result.scope());
		}
		if (result.idToken() != null) {
			response.put("id_token", result.idToken());
		}
		
		return Response.ok(response).build();
	}
	
	private Response errorResponse(String error, String description, Response.Status status) {
		Map<String, String> response = new HashMap<>();
		response.put("error", error);
		if (description != null) {
			response.put("error_description", description);
		}
		return Response.status(status).entity(response).build();
	}
	
	private Response.Status getStatusForError(String error) {
		return switch (error) {
			case "invalid_client", "unauthorized_client" -> Response.Status.UNAUTHORIZED;
			case "invalid_token" -> Response.Status.UNAUTHORIZED;
			case "invalid_grant", "invalid_request", "invalid_scope", 
					"unsupported_grant_type", "unsupported_token_type" -> Response.Status.BAD_REQUEST;
			case "server_error" -> Response.Status.INTERNAL_SERVER_ERROR;
			default -> Response.Status.BAD_REQUEST;
		};
	}
}
