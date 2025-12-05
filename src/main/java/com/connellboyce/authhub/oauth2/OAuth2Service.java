package com.connellboyce.authhub.oauth2;

import com.connellboyce.authhub.model.Actor;
import com.connellboyce.authhub.model.ActorType;
import com.connellboyce.authhub.model.dao.CBUser;
import com.connellboyce.authhub.model.dao.MongoRegisteredClient;
import com.connellboyce.authhub.service.ClientService;
import com.connellboyce.authhub.service.UserService;
import com.connellboyce.authhub.grant.TokenType;
import com.connellboyce.authhub.grant.AdditionalGrantTypes;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.mindrot.jbcrypt.BCrypt;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OAuth 2.0 Authorization Server Service.
 * Implements OAuth 2.1 and OpenID Connect 1.0 specifications.
 * 
 * <p><strong>Production Notes:</strong></p>
 * <ul>
 *   <li>Authorization codes and refresh tokens are stored in-memory. For production,
 *       implement persistent storage (e.g., Redis, MongoDB) to support horizontal scaling
 *       and persistence across restarts.</li>
 *   <li>The signing key pair is loaded from files or generated at startup. In production,
 *       use a stable key with proper key rotation strategy.</li>
 *   <li>The key ID is generated randomly at startup. For production with multiple instances,
 *       use a stable key ID or implement proper JWKS management.</li>
 * </ul>
 */
@ApplicationScoped
public class OAuth2Service {
	
	@Inject
	ClientService clientService;
	
	@Inject
	UserService userService;
	
	@ConfigProperty(name = "mp.jwt.verify.issuer")
	String issuer;
	
	@ConfigProperty(name = "smallrye.jwt.new-token.lifespan", defaultValue = "3600")
	long accessTokenLifespan;
	
	@ConfigProperty(name = "authhub.oauth2.refresh-token.lifespan", defaultValue = "2592000")
	long refreshTokenLifespan;
	
	@ConfigProperty(name = "smallrye.jwt.sign.key.location", defaultValue = "privateKey.pem")
	String privateKeyLocation;
	
	@ConfigProperty(name = "authhub.oauth2.public-key.location", defaultValue = "publicKey.pem")
	String publicKeyLocation;
	
	// In-memory stores (should be replaced with persistent storage in production)
	private final Map<String, AuthorizationCode> authorizationCodes = new ConcurrentHashMap<>();
	private final Map<String, RefreshTokenInfo> refreshTokens = new ConcurrentHashMap<>();
	
	private PrivateKey privateKey;
	private RSAPublicKey publicKey;
	private String keyId;
	
	@PostConstruct
	void init() {
		try {
			loadOrGenerateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException("Failed to initialize OAuth2Service", e);
		}
	}
	
	private void loadOrGenerateKeyPair() throws Exception {
		keyId = UUID.randomUUID().toString();
		
		// Try to load existing keys
		try {
			privateKey = loadPrivateKey();
			publicKey = loadPublicKey();
			return;
		} catch (Exception e) {
			// Keys not found, generate new ones
		}
		
		// Generate new key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = keyPair.getPrivate();
		publicKey = (RSAPublicKey) keyPair.getPublic();
	}
	
	private PrivateKey loadPrivateKey() throws Exception {
		InputStream is = getClass().getClassLoader().getResourceAsStream(privateKeyLocation);
		if (is == null) {
			throw new RuntimeException("Private key not found");
		}
		
		String key = new String(is.readAllBytes(), StandardCharsets.UTF_8);
		key = key.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replaceAll("\\s+", "");
		
		byte[] keyBytes = Base64.getDecoder().decode(key);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return factory.generatePrivate(spec);
	}
	
	private RSAPublicKey loadPublicKey() throws Exception {
		InputStream is = getClass().getClassLoader().getResourceAsStream(publicKeyLocation);
		if (is == null) {
			throw new RuntimeException("Public key not found");
		}
		
		String key = new String(is.readAllBytes(), StandardCharsets.UTF_8);
		key = key.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s+", "");
		
		byte[] keyBytes = Base64.getDecoder().decode(key);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return (RSAPublicKey) factory.generatePublic(spec);
	}
	
	/**
	 * Get the JSON Web Key Set for token verification.
	 */
	public Map<String, Object> getJwks() {
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.keyID(keyId)
				.algorithm(JWSAlgorithm.RS256)
				.build();
		
		Map<String, Object> jwks = new HashMap<>();
		jwks.put("keys", List.of(rsaKey.toJSONObject()));
		return jwks;
	}
	
	/**
	 * Create an authorization code for the authorization code flow.
	 */
	public String createAuthorizationCode(String clientId, String userId, String redirectUri, 
			Set<String> scopes, String codeChallenge, String codeChallengeMethod) {
		String code = UUID.randomUUID().toString();
		AuthorizationCode authCode = new AuthorizationCode(
				clientId, userId, redirectUri, scopes, codeChallenge, codeChallengeMethod,
				Instant.now().plusSeconds(600) // 10 minute expiry
		);
		authorizationCodes.put(code, authCode);
		return code;
	}
	
	/**
	 * Exchange an authorization code for tokens.
	 */
	public TokenResponse exchangeAuthorizationCode(String clientId, String clientSecret, 
			String code, String redirectUri, String codeVerifier) throws OAuth2Exception {
		
		// Validate client
		MongoRegisteredClient client = validateClient(clientId, clientSecret);
		if (!client.getAuthorizationGrantTypes().contains("authorization_code")) {
			throw new OAuth2Exception("unauthorized_client", "Client is not authorized for authorization_code grant");
		}
		
		// Validate and consume authorization code
		AuthorizationCode authCode = authorizationCodes.remove(code);
		if (authCode == null) {
			throw new OAuth2Exception("invalid_grant", "Invalid authorization code");
		}
		
		if (authCode.expiresAt().isBefore(Instant.now())) {
			throw new OAuth2Exception("invalid_grant", "Authorization code has expired");
		}
		
		if (!authCode.clientId().equals(clientId)) {
			throw new OAuth2Exception("invalid_grant", "Authorization code was not issued to this client");
		}
		
		if (!authCode.redirectUri().equals(redirectUri)) {
			throw new OAuth2Exception("invalid_grant", "Redirect URI mismatch");
		}
		
		// Validate PKCE if code challenge was provided
		if (authCode.codeChallenge() != null) {
			if (codeVerifier == null) {
				throw new OAuth2Exception("invalid_grant", "Code verifier required");
			}
			if (!validateCodeVerifier(codeVerifier, authCode.codeChallenge(), authCode.codeChallengeMethod())) {
				throw new OAuth2Exception("invalid_grant", "Invalid code verifier");
			}
		}
		
		// Get user info
		CBUser user = userService.getCBUserById(authCode.userId());
		if (user == null) {
			throw new OAuth2Exception("invalid_grant", "User not found");
		}
		
		// Generate tokens
		String accessToken = generateAccessToken(client, user, authCode.scopes());
		String refreshToken = null;
		String idToken = null;
		
		if (client.getAuthorizationGrantTypes().contains("refresh_token")) {
			refreshToken = generateRefreshToken(clientId, authCode.userId(), authCode.scopes());
		}
		
		if (authCode.scopes().contains("openid")) {
			idToken = generateIdToken(client, user, authCode.scopes());
		}
		
		return new TokenResponse(
				accessToken, "Bearer", accessTokenLifespan, refreshToken, 
				String.join(" ", authCode.scopes()), idToken
		);
	}
	
	/**
	 * Client credentials grant.
	 */
	public TokenResponse clientCredentialsGrant(String clientId, String clientSecret, String scope) 
			throws OAuth2Exception {
		
		MongoRegisteredClient client = validateClient(clientId, clientSecret);
		if (!client.getAuthorizationGrantTypes().contains("client_credentials")) {
			throw new OAuth2Exception("unauthorized_client", "Client is not authorized for client_credentials grant");
		}
		
		Set<String> scopes = parseScopes(scope);
		if (!client.getScopes().containsAll(scopes)) {
			throw new OAuth2Exception("invalid_scope", "Client is not authorized for the requested scope");
		}
		
		String accessToken = generateServiceAccessToken(client, scopes);
		
		return new TokenResponse(accessToken, "Bearer", accessTokenLifespan, null, 
				String.join(" ", scopes), null);
	}
	
	/**
	 * Refresh token grant.
	 */
	public TokenResponse refreshTokenGrant(String clientId, String clientSecret, String refreshToken, 
			String scope) throws OAuth2Exception {
		
		MongoRegisteredClient client = validateClient(clientId, clientSecret);
		if (!client.getAuthorizationGrantTypes().contains("refresh_token")) {
			throw new OAuth2Exception("unauthorized_client", "Client is not authorized for refresh_token grant");
		}
		
		RefreshTokenInfo tokenInfo = refreshTokens.get(refreshToken);
		if (tokenInfo == null) {
			throw new OAuth2Exception("invalid_grant", "Invalid refresh token");
		}
		
		if (tokenInfo.expiresAt().isBefore(Instant.now())) {
			refreshTokens.remove(refreshToken);
			throw new OAuth2Exception("invalid_grant", "Refresh token has expired");
		}
		
		if (!tokenInfo.clientId().equals(clientId)) {
			throw new OAuth2Exception("invalid_grant", "Refresh token was not issued to this client");
		}
		
		// Optionally narrow scope
		Set<String> requestedScopes = scope != null ? parseScopes(scope) : tokenInfo.scopes();
		if (!tokenInfo.scopes().containsAll(requestedScopes)) {
			throw new OAuth2Exception("invalid_scope", "Cannot request scopes not in original token");
		}
		
		CBUser user = userService.getCBUserById(tokenInfo.userId());
		if (user == null) {
			throw new OAuth2Exception("invalid_grant", "User not found");
		}
		
		// Generate new tokens (rotate refresh token)
		refreshTokens.remove(refreshToken);
		String newAccessToken = generateAccessToken(client, user, requestedScopes);
		String newRefreshToken = generateRefreshToken(clientId, tokenInfo.userId(), requestedScopes);
		String idToken = null;
		
		if (requestedScopes.contains("openid")) {
			idToken = generateIdToken(client, user, requestedScopes);
		}
		
		return new TokenResponse(newAccessToken, "Bearer", accessTokenLifespan, newRefreshToken, 
				String.join(" ", requestedScopes), idToken);
	}
	
	/**
	 * Token exchange grant (RFC 8693).
	 */
	public TokenResponse tokenExchangeGrant(String clientId, String clientSecret, String subjectToken,
			String subjectTokenType, String requestedTokenType, String scope) throws OAuth2Exception {
		
		MongoRegisteredClient client = validateClient(clientId, clientSecret);
		if (!client.getAuthorizationGrantTypes().contains(AdditionalGrantTypes.TOKEN_EXCHANGE)) {
			throw new OAuth2Exception("unauthorized_client", "Client is not authorized for token exchange grant");
		}
		
		// Validate subject token type
		Optional<TokenType> subjectType = TokenType.from(subjectTokenType);
		if (subjectType.isEmpty() || subjectType.get() != TokenType.ACCESS_TOKEN) {
			throw new OAuth2Exception("unsupported_token_type", 
					"OAuth 2.0 Token Exchange parameter: subject_token_type");
		}
		
		// Validate requested token type
		if (requestedTokenType != null && !requestedTokenType.isEmpty()) {
			Optional<TokenType> requestedType = TokenType.from(requestedTokenType);
			if (requestedType.isEmpty() || requestedType.get() != TokenType.ACCESS_TOKEN) {
				throw new OAuth2Exception("unsupported_token_type", 
						"OAuth 2.0 Token Exchange parameter: requested_token_type");
			}
		}
		
		// Parse and validate subject token
		SignedJWT subjectJwt;
		JWTClaimsSet subjectClaims;
		try {
			subjectJwt = SignedJWT.parse(subjectToken);
			subjectClaims = subjectJwt.getJWTClaimsSet();
		} catch (ParseException e) {
			throw new OAuth2Exception("invalid_grant", "Invalid subject_token");
		}
		
		Set<String> scopes = parseScopes(scope);
		if (!client.getScopes().containsAll(scopes)) {
			throw new OAuth2Exception("invalid_scope", "Client is not authorized for the requested scope");
		}
		
		// Build exchanged token with delegation chain
		String accessToken = generateExchangedToken(client, subjectClaims, scopes);
		
		return new TokenResponse(accessToken, "Bearer", accessTokenLifespan, null, 
				String.join(" ", scopes), null, "urn:ietf:params:oauth:token-type:access_token");
	}
	
	/**
	 * Introspect a token.
	 */
	public Map<String, Object> introspectToken(String token, String clientId, String clientSecret) 
			throws OAuth2Exception {
		
		validateClient(clientId, clientSecret);
		
		try {
			SignedJWT jwt = SignedJWT.parse(token);
			JWTClaimsSet claims = jwt.getJWTClaimsSet();
			
			// Check expiration
			if (claims.getExpirationTime() != null && 
					claims.getExpirationTime().toInstant().isBefore(Instant.now())) {
				return Map.of("active", false);
			}
			
			Map<String, Object> response = new HashMap<>();
			response.put("active", true);
			response.put("sub", claims.getSubject());
			response.put("client_id", claims.getClaim("azp"));
			response.put("scope", claims.getClaim("scope"));
			response.put("exp", claims.getExpirationTime().getTime() / 1000);
			response.put("iat", claims.getIssueTime().getTime() / 1000);
			response.put("iss", claims.getIssuer());
			response.put("token_type", "Bearer");
			
			if (claims.getClaim("username") != null) {
				response.put("username", claims.getClaim("username"));
			}
			
			return response;
			
		} catch (ParseException e) {
			return Map.of("active", false);
		}
	}
	
	/**
	 * Get user info from an access token.
	 */
	public Map<String, Object> getUserInfo(String accessToken) throws OAuth2Exception {
		try {
			SignedJWT jwt = SignedJWT.parse(accessToken);
			JWTClaimsSet claims = jwt.getJWTClaimsSet();
			
			// Check expiration
			if (claims.getExpirationTime() != null && 
					claims.getExpirationTime().toInstant().isBefore(Instant.now())) {
				throw new OAuth2Exception("invalid_token", "Token has expired");
			}
			
			String userId = claims.getSubject();
			CBUser user = userService.getCBUserById(userId);
			if (user == null) {
				throw new OAuth2Exception("invalid_token", "User not found");
			}
			
			Map<String, Object> response = new HashMap<>();
			response.put("sub", user.getId());
			response.put("preferred_username", user.getUsername());
			response.put("username", user.getUsername());
			response.put("name", user.getFirstName() + " " + user.getLastName());
			response.put("given_name", user.getFirstName());
			response.put("family_name", user.getLastName());
			response.put("email", user.getEmail());
			
			return response;
			
		} catch (ParseException e) {
			throw new OAuth2Exception("invalid_token", "Invalid access token");
		}
	}
	
	/**
	 * Get OpenID Connect discovery document.
	 */
	public Map<String, Object> getDiscoveryDocument(String baseUrl) {
		Map<String, Object> config = new HashMap<>();
		config.put("issuer", issuer);
		config.put("authorization_endpoint", baseUrl + "/oauth2/authorize");
		config.put("token_endpoint", baseUrl + "/oauth2/token");
		config.put("userinfo_endpoint", baseUrl + "/oauth2/userinfo");
		config.put("jwks_uri", baseUrl + "/oauth2/jwks");
		config.put("introspection_endpoint", baseUrl + "/oauth2/introspect");
		config.put("token_endpoint_auth_methods_supported", 
				List.of("client_secret_basic", "client_secret_post"));
		config.put("response_types_supported", List.of("code"));
		config.put("grant_types_supported", 
				List.of("authorization_code", "client_credentials", "refresh_token", 
						"urn:ietf:params:oauth:grant-type:token-exchange"));
		config.put("scopes_supported", List.of("openid", "profile", "email", "offline_access"));
		config.put("subject_types_supported", List.of("public"));
		config.put("id_token_signing_alg_values_supported", List.of("RS256"));
		config.put("claims_supported", 
				List.of("sub", "iss", "aud", "exp", "iat", "name", "email", "preferred_username"));
		config.put("code_challenge_methods_supported", List.of("S256", "plain"));
		return config;
	}
	
	// Helper methods
	
	private MongoRegisteredClient validateClient(String clientId, String clientSecret) throws OAuth2Exception {
		if (clientId == null || clientId.isEmpty()) {
			throw new OAuth2Exception("invalid_client", "client_id is required");
		}
		
		MongoRegisteredClient client = clientService.getClientByClientId(clientId);
		if (client == null) {
			throw new OAuth2Exception("invalid_client", "Unknown client");
		}
		
		if (clientSecret == null || clientSecret.isEmpty()) {
			throw new OAuth2Exception("invalid_client", "client_secret is required");
		}
		
		if (!BCrypt.checkpw(clientSecret, client.getClientSecret())) {
			throw new OAuth2Exception("invalid_client", "Invalid client credentials");
		}
		
		return client;
	}
	
	private Set<String> parseScopes(String scope) {
		if (scope == null || scope.isEmpty()) {
			return Set.of();
		}
		return new HashSet<>(Arrays.asList(scope.split("\\s+")));
	}
	
	private boolean validateCodeVerifier(String verifier, String challenge, String method) {
		if ("plain".equals(method)) {
			return verifier.equals(challenge);
		} else if ("S256".equals(method)) {
			try {
				java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
				byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
				String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
				return computed.equals(challenge);
			} catch (Exception e) {
				return false;
			}
		}
		return false;
	}
	
	private String generateAccessToken(MongoRegisteredClient client, CBUser user, Set<String> scopes) 
			throws OAuth2Exception {
		try {
			Instant now = Instant.now();
			JWTClaimsSet claims = new JWTClaimsSet.Builder()
					.issuer(issuer)
					.subject(user.getId())
					.issueTime(Date.from(now))
					.expirationTime(Date.from(now.plusSeconds(accessTokenLifespan)))
					.claim("azp", client.getClientId())
					.claim("scope", new ArrayList<>(scopes))
					.claim("username", user.getUsername())
					.claim("role", user.getRoles())
					.claim("amr", List.of("pwd"))
					.build();
			
			return signToken(claims);
		} catch (JOSEException e) {
			throw new OAuth2Exception("server_error", "Failed to generate access token");
		}
	}
	
	private String generateServiceAccessToken(MongoRegisteredClient client, Set<String> scopes) 
			throws OAuth2Exception {
		try {
			Instant now = Instant.now();
			JWTClaimsSet claims = new JWTClaimsSet.Builder()
					.issuer(issuer)
					.subject(client.getClientId())
					.issueTime(Date.from(now))
					.expirationTime(Date.from(now.plusSeconds(accessTokenLifespan)))
					.claim("azp", client.getClientId())
					.claim("scope", new ArrayList<>(scopes))
					.build();
			
			return signToken(claims);
		} catch (JOSEException e) {
			throw new OAuth2Exception("server_error", "Failed to generate access token");
		}
	}
	
	private String generateIdToken(MongoRegisteredClient client, CBUser user, Set<String> scopes) 
			throws OAuth2Exception {
		try {
			Instant now = Instant.now();
			JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
					.issuer(issuer)
					.subject(user.getId())
					.audience(client.getClientId())
					.issueTime(Date.from(now))
					.expirationTime(Date.from(now.plusSeconds(accessTokenLifespan)))
					.claim("azp", client.getClientId());
			
			if (scopes.contains("profile")) {
				builder.claim("name", user.getFirstName() + " " + user.getLastName());
				builder.claim("preferred_username", user.getUsername());
				builder.claim("given_name", user.getFirstName());
				builder.claim("family_name", user.getLastName());
			}
			
			if (scopes.contains("email")) {
				builder.claim("email", user.getEmail());
			}
			
			return signToken(builder.build());
		} catch (JOSEException e) {
			throw new OAuth2Exception("server_error", "Failed to generate ID token");
		}
	}
	
	private String generateRefreshToken(String clientId, String userId, Set<String> scopes) {
		String token = UUID.randomUUID().toString();
		RefreshTokenInfo info = new RefreshTokenInfo(
				clientId, userId, scopes, Instant.now().plusSeconds(refreshTokenLifespan)
		);
		refreshTokens.put(token, info);
		return token;
	}
	
	private String generateExchangedToken(MongoRegisteredClient client, JWTClaimsSet subjectClaims, 
			Set<String> scopes) throws OAuth2Exception {
		try {
			Instant now = Instant.now();
			
			// Build actor claim chain
			Object existingActClaim = subjectClaims.getClaim("act");
			Actor existingActor = Actor.from(existingActClaim);
			Actor actor = new Actor(client.getClientId(), ActorType.SERVICE, existingActor);
			
			ObjectMapper mapper = new ObjectMapper()
					.setSerializationInclusion(JsonInclude.Include.NON_NULL);
			@SuppressWarnings("unchecked")
			Map<String, Object> actorMap = mapper.convertValue(actor, Map.class);
			
			JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
					.issuer(issuer)
					.issueTime(Date.from(now))
					.expirationTime(Date.from(now.plusSeconds(accessTokenLifespan)))
					.claim("azp", client.getClientId())
					.claim("scope", new ArrayList<>(scopes))
					.claim("act", actorMap);
			
			// Delegate claims from subject token
			if (subjectClaims.getSubject() != null) {
				builder.subject(subjectClaims.getSubject());
			} else {
				builder.subject(client.getClientId());
			}
			
			if (subjectClaims.getClaim("username") != null) {
				builder.claim("username", subjectClaims.getClaim("username"));
			}
			if (subjectClaims.getClaim("amr") != null) {
				builder.claim("amr", subjectClaims.getClaim("amr"));
			}
			if (subjectClaims.getClaim("role") != null) {
				builder.claim("role", subjectClaims.getClaim("role"));
			}
			
			return signToken(builder.build());
		} catch (JOSEException e) {
			throw new OAuth2Exception("server_error", "Failed to generate exchanged token");
		}
	}
	
	private String signToken(JWTClaimsSet claims) throws JOSEException {
		JWSSigner signer = new RSASSASigner(privateKey);
		SignedJWT signedJWT = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
				claims
		);
		signedJWT.sign(signer);
		return signedJWT.serialize();
	}
	
	// Record types
	
	public record AuthorizationCode(
			String clientId,
			String userId,
			String redirectUri,
			Set<String> scopes,
			String codeChallenge,
			String codeChallengeMethod,
			Instant expiresAt
	) {}
	
	public record RefreshTokenInfo(
			String clientId,
			String userId,
			Set<String> scopes,
			Instant expiresAt
	) {}
	
	public record TokenResponse(
			String accessToken,
			String tokenType,
			long expiresIn,
			String refreshToken,
			String scope,
			String idToken,
			String issuedTokenType
	) {
		public TokenResponse(String accessToken, String tokenType, long expiresIn, 
				String refreshToken, String scope, String idToken) {
			this(accessToken, tokenType, expiresIn, refreshToken, scope, idToken, null);
		}
	}
	
	public static class OAuth2Exception extends Exception {
		private final String error;
		
		public OAuth2Exception(String error, String message) {
			super(message);
			this.error = error;
		}
		
		public String getError() {
			return error;
		}
	}
}
