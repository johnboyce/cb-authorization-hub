package com.connellboyce.authhub.filter;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JAX-RS filter to capture authorization request parameters.
 * In Quarkus, we use ContainerRequestFilter instead of servlet Filter.
 */
@Provider
@ApplicationScoped
public class AuthorizationRequestFilter implements ContainerRequestFilter {
	
	// Simple in-memory session storage for preserved params
	// In production, this should be a distributed cache or proper session management
	private static final Map<String, Map<String, String>> sessionParams = new ConcurrentHashMap<>();
	
	@ConfigProperty(name = "authhub.security.login.preserved-params", defaultValue = "client_id")
	String preservedParamsConfig;

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		Set<String> preservedParams = Set.of(preservedParamsConfig.split(","));
		String sessionId = getOrCreateSessionId(requestContext);
		
		preservedParams.forEach(param -> {
			String value = requestContext.getUriInfo().getQueryParameters().getFirst(param);
			if (value != null) {
				sessionParams.computeIfAbsent(sessionId, k -> new ConcurrentHashMap<>())
						.put("auth_param_" + param, value);
			}
		});
	}
	
	private String getOrCreateSessionId(ContainerRequestContext requestContext) {
		// Use a header or cookie for session tracking
		String sessionId = requestContext.getHeaderString("X-Session-Id");
		if (sessionId == null) {
			sessionId = java.util.UUID.randomUUID().toString();
		}
		return sessionId;
	}
	
	/**
	 * Get a preserved parameter value for a session.
	 */
	public static Optional<String> getPreservedParam(String sessionId, String paramName) {
		Map<String, String> params = sessionParams.get(sessionId);
		if (params != null) {
			return Optional.ofNullable(params.get("auth_param_" + paramName));
		}
		return Optional.empty();
	}
	
	/**
	 * Get all preserved parameters for a session.
	 */
	public static Map<String, String> getPreservedParams(String sessionId) {
		return sessionParams.getOrDefault(sessionId, Map.of());
	}
}
