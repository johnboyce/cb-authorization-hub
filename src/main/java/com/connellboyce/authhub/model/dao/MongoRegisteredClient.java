package com.connellboyce.authhub.model.dao;

import io.quarkus.mongodb.panache.common.MongoEntity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bson.codecs.pojo.annotations.BsonId;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@MongoEntity(collection = "clients")
public class MongoRegisteredClient {
	@BsonId
	private String id;
	private String clientId;
	private String clientSecret;
	private Set<String> clientAuthenticationMethods;
	private Set<String> authorizationGrantTypes;
	private Set<String> redirectUris;
	private Set<String> scopes;
	private boolean requireAuthorizationConsent;
	private String ownerId;
	private boolean useCustomTheme;
}
