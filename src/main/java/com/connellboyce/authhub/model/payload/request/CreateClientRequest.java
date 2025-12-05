package com.connellboyce.authhub.model.payload.request;

import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class CreateClientRequest {
	private String clientId;
	private String clientSecret;
	private List<String> redirectUris;
	private List<String> scopes;
	private List<String> grantTypes;

	/**
	 * Creates a RegisteredClient representation for use in OAuth operations.
	 * Note: In Quarkus, we handle this differently than Spring Authorization Server.
	 */
	public static ClientRegistration toClientRegistration(String clientId, String clientSecret, List<String> redirectUris, List<String> scopes, List<String> grantTypes) {
		return new ClientRegistration(
				String.valueOf(UUID.randomUUID()),
				clientId,
				clientSecret,
				redirectUris,
				scopes,
				grantTypes
		);
	}

	/**
	 * Simple POJO to represent a client registration.
	 */
	public record ClientRegistration(
			String id,
			String clientId,
			String clientSecret,
			List<String> redirectUris,
			List<String> scopes,
			List<String> grantTypes
	) {}
}
