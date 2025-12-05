package com.connellboyce.authhub.oauth2;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;

/**
 * Integration tests for OAuth2 UserInfo Endpoint.
 */
@QuarkusTest
public class OAuth2UserInfoEndpointTest {

	@Test
	public void testUserInfoRequiresAuthorization() {
		given()
			.when()
			.get("/oauth2/userinfo")
			.then()
			.statusCode(401)
			.body("error", is("invalid_token"))
			.body("error_description", containsString("Access token required"));
	}

	@Test
	public void testUserInfoRequiresBearerToken() {
		given()
			.header("Authorization", "Basic invalid")
			.when()
			.get("/oauth2/userinfo")
			.then()
			.statusCode(401)
			.body("error", is("invalid_token"));
	}
}
