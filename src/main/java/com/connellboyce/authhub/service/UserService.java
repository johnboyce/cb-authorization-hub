package com.connellboyce.authhub.service;

import com.connellboyce.authhub.model.dao.CBUser;
import io.quarkus.security.identity.SecurityIdentity;

public interface UserService {
	CBUser createUser(String username, String password, String email, String firstName, String lastName) throws IllegalArgumentException;
	CBUser getCBUserByUsername(String username);
}
