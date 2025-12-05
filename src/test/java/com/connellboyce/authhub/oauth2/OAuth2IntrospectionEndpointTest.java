package com.connellboyce.authhub.oauth2;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;

/**
 * Integration tests for OAuth2 Introspection Endpoint.
 */
@QuarkusTest
public class OAuth2IntrospectionEndpointTest {

	@Test
	public void testIntrospectionRequiresClientCredentials() {
		given()
			.contentType(ContentType.URLENC)
			.formParam("token", "some-token")
			.when()
			.post("/oauth2/introspect")
			.then()
			.statusCode(401)
			.body("error", is("invalid_client"));
	}
}
