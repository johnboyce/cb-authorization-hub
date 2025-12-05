package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.model.dao.CBUser;
import com.connellboyce.authhub.model.dao.MongoRegisteredClient;
import com.connellboyce.authhub.oauth2.OAuth2Service;
import com.connellboyce.authhub.service.ClientService;
import com.connellboyce.authhub.service.UserService;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import java.net.URI;
import java.util.*;

/**
 * OAuth 2.0 Authorization Endpoint Controller.
 * Handles the authorization code flow including consent.
 */
@Path("/oauth2")
public class OAuth2AuthorizationController {
	
	@Inject
	OAuth2Service oauth2Service;
	
	@Inject
	ClientService clientService;
	
	@Inject
	UserService userService;
	
	@Inject
	SecurityIdentity identity;
	
	@Inject
	Template consent;
	
	// In-memory pending authorizations (should be session-based in production)
	private static final Map<String, PendingAuthorization> pendingAuthorizations = new java.util.concurrent.ConcurrentHashMap<>();
	
	/**
	 * OAuth 2.0 Authorization Endpoint.
	 * Handles GET requests for authorization code flow.
	 */
	@GET
	@Path("/authorize")
	@Produces(MediaType.TEXT_HTML)
	public Response authorize(
			@QueryParam("response_type") String responseType,
			@QueryParam("client_id") String clientId,
			@QueryParam("redirect_uri") String redirectUri,
			@QueryParam("scope") String scope,
			@QueryParam("state") String state,
			@QueryParam("code_challenge") String codeChallenge,
			@QueryParam("code_challenge_method") String codeChallengeMethod,
			@QueryParam("nonce") String nonce) {
		
		// Validate response_type
		if (!"code".equals(responseType)) {
			return errorRedirect(redirectUri, "unsupported_response_type", 
					"Only 'code' response type is supported", state);
		}
		
		// Validate client
		MongoRegisteredClient client = clientService.getClientByClientId(clientId);
		if (client == null) {
			return Response.status(Response.Status.BAD_REQUEST)
					.entity("Invalid client_id")
					.build();
		}
		
		// Validate redirect_uri
		if (redirectUri == null || !client.getRedirectUris().contains(redirectUri)) {
			return Response.status(Response.Status.BAD_REQUEST)
					.entity("Invalid redirect_uri")
					.build();
		}
		
		// Validate scopes
		Set<String> requestedScopes = parseScopes(scope);
		if (!client.getScopes().containsAll(requestedScopes)) {
			return errorRedirect(redirectUri, "invalid_scope", 
					"Client is not authorized for the requested scope", state);
		}
		
		// Check if user is authenticated
		if (identity.isAnonymous()) {
			// Redirect to login with return URL
			String loginUrl = "/login?redirect=" + encodeParam("/oauth2/authorize?" + buildQueryString(
					responseType, clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, nonce));
			return Response.temporaryRedirect(URI.create(loginUrl)).build();
		}
		
		// Check if consent is required
		if (client.isRequireAuthorizationConsent()) {
			// Store pending authorization and show consent page
			String authId = UUID.randomUUID().toString();
			pendingAuthorizations.put(authId, new PendingAuthorization(
					clientId, redirectUri, requestedScopes, state, codeChallenge, codeChallengeMethod, nonce
			));
			
			TemplateInstance consentPage = consent
					.data("authId", authId)
					.data("clientId", clientId)
					.data("scopes", requestedScopes);
			
			return Response.ok(consentPage.render()).build();
		}
		
		// No consent required, issue authorization code directly
		return issueAuthorizationCode(clientId, redirectUri, requestedScopes, state, 
				codeChallenge, codeChallengeMethod);
	}
	
	/**
	 * Handle consent form submission.
	 */
	@POST
	@Path("/authorize/consent")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response handleConsent(
			@FormParam("auth_id") String authId,
			@FormParam("action") String action) {
		
		PendingAuthorization pending = pendingAuthorizations.remove(authId);
		if (pending == null) {
			return Response.status(Response.Status.BAD_REQUEST)
					.entity("Invalid or expired authorization request")
					.build();
		}
		
		if ("deny".equals(action)) {
			return errorRedirect(pending.redirectUri(), "access_denied", 
					"User denied the authorization request", pending.state());
		}
		
		return issueAuthorizationCode(pending.clientId(), pending.redirectUri(), 
				pending.scopes(), pending.state(), pending.codeChallenge(), pending.codeChallengeMethod());
	}
	
	private Response issueAuthorizationCode(String clientId, String redirectUri, 
			Set<String> scopes, String state, String codeChallenge, String codeChallengeMethod) {
		
		// Get current user
		String username = identity.getPrincipal().getName();
		CBUser user = userService.getCBUserByUsername(username);
		if (user == null) {
			return errorRedirect(redirectUri, "server_error", "User not found", state);
		}
		
		// Create authorization code
		String code = oauth2Service.createAuthorizationCode(
				clientId, user.getId(), redirectUri, scopes, codeChallenge, codeChallengeMethod);
		
		// Build redirect URI with code
		UriBuilder builder = UriBuilder.fromUri(redirectUri).queryParam("code", code);
		if (state != null) {
			builder.queryParam("state", state);
		}
		
		return Response.temporaryRedirect(builder.build()).build();
	}
	
	private Response errorRedirect(String redirectUri, String error, String description, String state) {
		if (redirectUri == null) {
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(error + ": " + description)
					.build();
		}
		
		UriBuilder builder = UriBuilder.fromUri(redirectUri)
				.queryParam("error", error)
				.queryParam("error_description", description);
		if (state != null) {
			builder.queryParam("state", state);
		}
		
		return Response.temporaryRedirect(builder.build()).build();
	}
	
	private Set<String> parseScopes(String scope) {
		if (scope == null || scope.isEmpty()) {
			return Set.of();
		}
		return new HashSet<>(Arrays.asList(scope.split("\\s+")));
	}
	
	private String buildQueryString(String responseType, String clientId, String redirectUri,
			String scope, String state, String codeChallenge, String codeChallengeMethod, String nonce) {
		StringBuilder sb = new StringBuilder();
		sb.append("response_type=").append(encodeParam(responseType));
		sb.append("&client_id=").append(encodeParam(clientId));
		sb.append("&redirect_uri=").append(encodeParam(redirectUri));
		if (scope != null) sb.append("&scope=").append(encodeParam(scope));
		if (state != null) sb.append("&state=").append(encodeParam(state));
		if (codeChallenge != null) sb.append("&code_challenge=").append(encodeParam(codeChallenge));
		if (codeChallengeMethod != null) sb.append("&code_challenge_method=").append(encodeParam(codeChallengeMethod));
		if (nonce != null) sb.append("&nonce=").append(encodeParam(nonce));
		return sb.toString();
	}
	
	private String encodeParam(String value) {
		try {
			return java.net.URLEncoder.encode(value, "UTF-8");
		} catch (Exception e) {
			return value;
		}
	}
	
	private record PendingAuthorization(
			String clientId,
			String redirectUri,
			Set<String> scopes,
			String state,
			String codeChallenge,
			String codeChallengeMethod,
			String nonce
	) {}
}
