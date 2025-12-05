package com.connellboyce.authhub.controller;

import com.connellboyce.authhub.oauth2.OAuth2Service;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import java.util.Map;

/**
 * OpenID Connect Discovery Endpoint.
 * Provides the .well-known/openid-configuration document.
 */
@Path("")
@Produces(MediaType.APPLICATION_JSON)
public class OAuth2DiscoveryController {
	
	@Inject
	OAuth2Service oauth2Service;
	
	@Context
	UriInfo uriInfo;
	
	/**
	 * OpenID Connect Discovery Document.
	 */
	@GET
	@Path("/.well-known/openid-configuration")
	public Response openidConfiguration() {
		String baseUrl = getBaseUrl();
		Map<String, Object> config = oauth2Service.getDiscoveryDocument(baseUrl);
		return Response.ok(config).build();
	}
	
	/**
	 * OAuth 2.0 Authorization Server Metadata (RFC 8414).
	 */
	@GET
	@Path("/.well-known/oauth-authorization-server")
	public Response oauthMetadata() {
		return openidConfiguration();
	}
	
	private String getBaseUrl() {
		// Build base URL from request
		String scheme = uriInfo.getBaseUri().getScheme();
		String host = uriInfo.getBaseUri().getHost();
		int port = uriInfo.getBaseUri().getPort();
		
		StringBuilder baseUrl = new StringBuilder();
		baseUrl.append(scheme).append("://").append(host);
		if (port > 0 && port != 80 && port != 443) {
			baseUrl.append(":").append(port);
		}
		return baseUrl.toString();
	}
}
