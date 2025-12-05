package com.connellboyce.authhub.oauth2;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;

/**
 * Integration tests for OAuth2 Discovery Endpoints.
 */
@QuarkusTest
public class OAuth2DiscoveryEndpointTest {

	@Test
	public void testOpenIdConfiguration() {
		given()
			.when()
			.get("/.well-known/openid-configuration")
			.then()
			.statusCode(200)
			.body("issuer", notNullValue())
			.body("authorization_endpoint", containsString("/oauth2/authorize"))
			.body("token_endpoint", containsString("/oauth2/token"))
			.body("userinfo_endpoint", containsString("/oauth2/userinfo"))
			.body("jwks_uri", containsString("/oauth2/jwks"))
			.body("introspection_endpoint", containsString("/oauth2/introspect"))
			.body("response_types_supported", hasItem("code"))
			.body("grant_types_supported", hasItems("authorization_code", "client_credentials", "refresh_token"))
			.body("grant_types_supported", hasItem("urn:ietf:params:oauth:grant-type:token-exchange"))
			.body("subject_types_supported", hasItem("public"))
			.body("id_token_signing_alg_values_supported", hasItem("RS256"))
			.body("code_challenge_methods_supported", hasItems("S256", "plain"));
	}

	@Test
	public void testOAuthMetadata() {
		given()
			.when()
			.get("/.well-known/oauth-authorization-server")
			.then()
			.statusCode(200)
			.body("issuer", notNullValue())
			.body("token_endpoint", containsString("/oauth2/token"));
	}

	@Test
	public void testJwksEndpoint() {
		given()
			.when()
			.get("/oauth2/jwks")
			.then()
			.statusCode(200)
			.body("keys", notNullValue())
			.body("keys.size()", is(1))
			.body("keys[0].kty", is("RSA"))
			.body("keys[0].alg", is("RS256"))
			.body("keys[0].kid", notNullValue())
			.body("keys[0].n", notNullValue())
			.body("keys[0].e", notNullValue());
	}
}
