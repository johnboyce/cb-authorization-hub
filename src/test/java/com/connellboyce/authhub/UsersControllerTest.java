package com.connellboyce.authhub;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;

@QuarkusTest
public class UsersControllerTest {

    @Test
    public void testCreateUserEndpoint() {
        // Test that the endpoint returns 400 when required fields are missing
        given()
            .contentType("application/json")
            .body("{}")
            .when().post("/api/v1/user")
            .then()
            .statusCode(400);
    }
}
