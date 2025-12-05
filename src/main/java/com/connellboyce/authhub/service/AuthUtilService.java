package com.connellboyce.authhub.service;

import io.quarkus.security.identity.SecurityIdentity;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.Optional;

public interface AuthUtilService {
	Optional<String> getUserIdFromSecurityIdentity(SecurityIdentity identity);
}
