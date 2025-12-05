package com.connellboyce.authhub.service;

import com.connellboyce.authhub.model.dao.CBUser;
import com.connellboyce.authhub.repository.UserRepository;
import com.connellboyce.authhub.util.CBRole;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.mindrot.jbcrypt.BCrypt;

import java.util.Set;
import java.util.UUID;

@ApplicationScoped
public class UserServiceImpl implements UserService {
	
	@Inject
	UserRepository userRepository;

	@Override
	@Transactional
	public CBUser createUser(String username, String password, String email, String firstName, String lastName) throws IllegalArgumentException {
		String id = String.valueOf(UUID.randomUUID());
		CBUser newUser = new CBUser(
				id,
				username,
				BCrypt.hashpw(password, BCrypt.gensalt()),
				Set.of(CBRole.ROLE_USER.withoutPrefix()),
				email,
				firstName,
				lastName
		);
		
		userRepository.findByIdString(id).ifPresent(existingUser -> {
			throw new IllegalArgumentException("User ID already exists");
		});
		userRepository.findByUsername(username).ifPresent(existingUser -> {
			throw new IllegalArgumentException("Username already exists");
		});
		userRepository.findByEmail(email).ifPresent(existingUser -> {
			throw new IllegalArgumentException("Email already exists");
		});

		userRepository.persist(newUser);

		return newUser;
	}

	@Override
	public CBUser getCBUserByUsername(String username) {
		return userRepository.findByUsername(username).orElse(null);
	}
}
