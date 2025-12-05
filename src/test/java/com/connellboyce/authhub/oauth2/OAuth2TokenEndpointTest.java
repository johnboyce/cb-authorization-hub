package com.connellboyce.authhub.oauth2;

import com.connellboyce.authhub.grant.AdditionalGrantTypes;
import com.connellboyce.authhub.grant.TokenType;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;

/**
 * Integration tests for OAuth2 Token Endpoint.
 * Note: These tests run without a full database, so they verify error handling.
 */
@QuarkusTest
public class OAuth2TokenEndpointTest {

	@Test
	public void testTokenEndpointRequiresGrantType() {
		given()
			.contentType(ContentType.URLENC)
			.when()
			.post("/oauth2/token")
			.then()
			.statusCode(400)
			.body("error", is("invalid_request"))
			.body("error_description", containsString("grant_type"));
	}

	@Test
	public void testClientCredentialsRequiresClientId() {
		given()
			.contentType(ContentType.URLENC)
			.formParam("grant_type", "client_credentials")
			.when()
			.post("/oauth2/token")
			.then()
			.statusCode(401)
			.body("error", is("invalid_client"))
			.body("error_description", containsString("client_id"));
	}

	@Test
	public void testUnsupportedGrantType() {
		given()
			.contentType(ContentType.URLENC)
			.formParam("grant_type", "unsupported_type")
			.when()
			.post("/oauth2/token")
			.then()
			.statusCode(400)
			.body("error", is("unsupported_grant_type"));
	}
}
