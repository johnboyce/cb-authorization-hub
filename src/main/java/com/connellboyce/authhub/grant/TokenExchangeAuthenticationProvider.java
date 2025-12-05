package com.connellboyce.authhub.grant;

import com.connellboyce.authhub.model.Actor;
import com.connellboyce.authhub.model.ActorType;
import com.connellboyce.authhub.model.dao.MongoRegisteredClient;
import com.connellboyce.authhub.service.ClientService;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.smallrye.jwt.auth.principal.JWTParser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.mindrot.jbcrypt.BCrypt;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

/**
 * OAuth 2.0 Token Exchange: RFC 8693
 * A service that handles token exchange requests in a Quarkus context.
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693">RFC 8693</a>
 */
@ApplicationScoped
public class TokenExchangeAuthenticationProvider {
	
	@Inject
	ClientService clientService;
	
	@Inject
	JWTParser jwtParser;
	
	@ConfigProperty(name = "mp.jwt.verify.issuer")
	String issuer;
	
	@ConfigProperty(name = "smallrye.jwt.new-token.lifespan", defaultValue = "3600")
	long tokenLifespan;
	
	@ConfigProperty(name = "smallrye.jwt.sign.key.location")
	String privateKeyLocation;
	
	private PrivateKey cachedPrivateKey;
	
	/**
	 * Result of a token exchange operation.
	 */
	public record TokenExchangeResult(
			String accessToken,
			String tokenType,
			long expiresIn,
			String scope,
			String issuedTokenType
	) {}
	
	/**
	 * Error response for token exchange failures.
	 */
	public record TokenExchangeError(
			String error,
			String errorDescription,
			String errorUri
	) {}
	
	/**
	 * Authenticate and process a token exchange request.
	 *
	 * @param clientId The client ID
	 * @param clientSecret The client secret
	 * @param subjectToken The subject token to exchange
	 * @param subjectTokenType The type of the subject token
	 * @param requestedTokenType The requested token type (optional)
	 * @param scope The requested scopes (optional)
	 * @param actorToken The actor token (optional)
	 * @param actorTokenType The type of the actor token (optional)
	 * @return A TokenExchangeResult on success
	 * @throws TokenExchangeException if the exchange fails
	 */
	public TokenExchangeResult exchange(
			String clientId,
			String clientSecret,
			String subjectToken,
			String subjectTokenType,
			String requestedTokenType,
			String scope,
			String actorToken,
			String actorTokenType) throws TokenExchangeException {
		
		// Validate client authentication
		MongoRegisteredClient client = validateClientAuthentication(clientId, clientSecret);
		
		// Validate subject token parameters
		if (subjectToken == null || subjectToken.isEmpty()) {
			throw new TokenExchangeException("invalid_request", "subject_token is required", 
					"https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
		}
		
		Optional<TokenType> subjectTokenTypeEnum = TokenType.from(subjectTokenType);
		if (subjectTokenTypeEnum.isEmpty()) {
			throw new TokenExchangeException("unsupported_token_type", 
					"OAuth 2.0 Token Exchange parameter: subject_token_type",
					"https://datatracker.ietf.org/doc/html/rfc8693#section-2.1");
		}
		
		if (subjectTokenTypeEnum.get() != TokenType.ACCESS_TOKEN) {
			throw new TokenExchangeException("unsupported_token_type", 
					"Only access_token subject_token_type is supported",
					"https://datatracker.ietf.org/doc/html/rfc8693#section-2.1");
		}
		
		// Validate requested token type if provided
		if (requestedTokenType != null && !requestedTokenType.isEmpty()) {
			Optional<TokenType> requestedTokenTypeEnum = TokenType.from(requestedTokenType);
			if (requestedTokenTypeEnum.isEmpty()) {
				throw new TokenExchangeException("unsupported_token_type", 
						"OAuth 2.0 Token Exchange parameter: requested_token_type",
						"https://datatracker.ietf.org/doc/html/rfc8693#section-2.1");
			}
			if (requestedTokenTypeEnum.get() != TokenType.ACCESS_TOKEN) {
				throw new TokenExchangeException("unsupported_token_type", 
						"Only access_token requested_token_type is supported",
						"https://datatracker.ietf.org/doc/html/rfc8693#section-2.1");
			}
		}
		
		// Decode and validate the subject token
		SignedJWT subjectJwt;
		JWTClaimsSet subjectClaims;
		try {
			subjectJwt = SignedJWT.parse(subjectToken);
			subjectClaims = subjectJwt.getJWTClaimsSet();
		} catch (ParseException e) {
			throw new TokenExchangeException("invalid_grant", "Invalid subject_token", null);
		}
		
		// Validate scope against client's allowed scopes
		Set<String> requestedScopes = parseScopes(scope);
		if (!client.getScopes().containsAll(requestedScopes)) {
			throw new TokenExchangeException("invalid_scope", 
					"Client is not authorized for the requested scope",
					"https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
		}
		
		// Build the new access token with delegation chain
		String newAccessToken = buildExchangedToken(client, subjectClaims, requestedScopes);
		
		return new TokenExchangeResult(
				newAccessToken,
				"Bearer",
				tokenLifespan,
				String.join(" ", requestedScopes),
				"urn:ietf:params:oauth:token-type:access_token"
		);
	}
	
	private MongoRegisteredClient validateClientAuthentication(String clientId, String clientSecret) 
			throws TokenExchangeException {
		if (clientId == null || clientId.isEmpty()) {
			throw new TokenExchangeException("invalid_client", "client_id is required", null);
		}
		if (clientSecret == null || clientSecret.isEmpty()) {
			throw new TokenExchangeException("invalid_client", "client_secret is required", null);
		}
		
		MongoRegisteredClient client = clientService.getClientByClientId(clientId);
		if (client == null) {
			throw new TokenExchangeException("invalid_client", "Unknown client", null);
		}
		
		// Validate client secret using BCrypt
		if (!BCrypt.checkpw(clientSecret, client.getClientSecret())) {
			throw new TokenExchangeException("invalid_client", "Invalid client credentials", null);
		}
		
		// Check if client is authorized for token exchange
		if (!client.getAuthorizationGrantTypes().contains(AdditionalGrantTypes.TOKEN_EXCHANGE)) {
			throw new TokenExchangeException("unauthorized_client", 
					"Client is not authorized for token exchange grant type", null);
		}
		
		return client;
	}
	
	private Set<String> parseScopes(String scope) {
		if (scope == null || scope.isEmpty()) {
			return Set.of();
		}
		return new HashSet<>(Arrays.asList(scope.split("\\s+")));
	}
	
	private String buildExchangedToken(MongoRegisteredClient client, JWTClaimsSet subjectClaims, 
			Set<String> scopes) throws TokenExchangeException {
		try {
			Instant now = Instant.now();
			Instant expiration = now.plusSeconds(tokenLifespan);
			
			// Build the actor claim chain
			Object existingActClaim = subjectClaims.getClaim("act");
			Actor existingActor = Actor.from(existingActClaim);
			Actor actor = new Actor(client.getClientId(), ActorType.SERVICE, existingActor);
			
			ObjectMapper mapper = new ObjectMapper()
					.setSerializationInclusion(JsonInclude.Include.NON_NULL);
			@SuppressWarnings("unchecked")
			Map<String, Object> actorMap = mapper.convertValue(actor, Map.class);
			
			// Build claims for the new token
			JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
					.issuer(issuer)
					.issueTime(Date.from(now))
					.expirationTime(Date.from(expiration))
					.claim("azp", client.getClientId())
					.claim("scope", new ArrayList<>(scopes))
					.claim("act", actorMap);
			
			// Delegate claims from the subject token
			delegateClaimIfPresent(subjectClaims, claimsBuilder, "sub");
			delegateClaimIfPresent(subjectClaims, claimsBuilder, "username");
			delegateClaimIfPresent(subjectClaims, claimsBuilder, "amr");
			delegateClaimIfPresent(subjectClaims, claimsBuilder, "role");
			
			// If no subject was delegated, use the client ID as subject
			if (subjectClaims.getSubject() == null || subjectClaims.getSubject().isEmpty()) {
				claimsBuilder.subject(client.getClientId());
			}
			
			JWTClaimsSet claims = claimsBuilder.build();
			
			// Sign the token
			PrivateKey privateKey = getPrivateKey();
			JWSSigner signer = new RSASSASigner(privateKey);
			
			SignedJWT signedJWT = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.RS256)
							.keyID(UUID.randomUUID().toString())
							.build(),
					claims
			);
			signedJWT.sign(signer);
			
			return signedJWT.serialize();
			
		} catch (JOSEException e) {
			throw new TokenExchangeException("server_error", "Failed to sign token", null);
		}
	}
	
	private void delegateClaimIfPresent(JWTClaimsSet source, JWTClaimsSet.Builder target, String claimName) {
		Object value = source.getClaim(claimName);
		if (value != null) {
			if ("sub".equals(claimName)) {
				target.subject((String) value);
			} else {
				target.claim(claimName, value);
			}
		}
	}
	
	private PrivateKey getPrivateKey() throws TokenExchangeException {
		if (cachedPrivateKey != null) {
			return cachedPrivateKey;
		}
		
		try {
			InputStream is = getClass().getClassLoader().getResourceAsStream(privateKeyLocation);
			if (is == null) {
				throw new TokenExchangeException("server_error", "Private key not found", null);
			}
			
			String key = new String(is.readAllBytes(), StandardCharsets.UTF_8);
			// Handle PEM format
			key = key.replace("-----BEGIN PRIVATE KEY-----", "")
					.replace("-----END PRIVATE KEY-----", "")
					.replaceAll("\\s+", "");
			
			byte[] keyBytes = Base64.getDecoder().decode(key);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			cachedPrivateKey = factory.generatePrivate(spec);
			return cachedPrivateKey;
			
		} catch (Exception e) {
			throw new TokenExchangeException("server_error", "Failed to load private key: " + e.getMessage(), null);
		}
	}
	
	/**
	 * Exception thrown when token exchange fails.
	 */
	public static class TokenExchangeException extends Exception {
		private final String error;
		private final String errorDescription;
		private final String errorUri;
		
		public TokenExchangeException(String error, String errorDescription, String errorUri) {
			super(errorDescription);
			this.error = error;
			this.errorDescription = errorDescription;
			this.errorUri = errorUri;
		}
		
		public String getError() {
			return error;
		}
		
		public String getErrorDescription() {
			return errorDescription;
		}
		
		public String getErrorUri() {
			return errorUri;
		}
		
		public TokenExchangeError toErrorResponse() {
			return new TokenExchangeError(error, errorDescription, errorUri);
		}
	}
}
