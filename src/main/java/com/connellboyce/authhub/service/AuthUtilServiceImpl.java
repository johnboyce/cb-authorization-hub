package com.connellboyce.authhub.service;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.Optional;

@ApplicationScoped
public class AuthUtilServiceImpl implements AuthUtilService {
	
	@Inject
	UserService userService;

	@Override
	public Optional<String> getUserIdFromSecurityIdentity(SecurityIdentity identity) {
		if (identity == null || identity.isAnonymous()) {
			return Optional.empty();
		}
		
		// If we have a JWT token, get the subject claim
		if (identity.getPrincipal() instanceof JsonWebToken jwt) {
			String username = jwt.getClaim("username");
			if (username != null) {
				return Optional.ofNullable(jwt.getSubject());
			}
			return Optional.empty();
		}
		
		// Otherwise, look up the user by username
		String username = identity.getPrincipal().getName();
		var user = userService.getCBUserByUsername(username);
		if (user != null) {
			return Optional.of(user.getId());
		}
		
		return Optional.empty();
	}
}
