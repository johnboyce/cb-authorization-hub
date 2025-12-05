package com.connellboyce.authhub.grant;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for TokenType enum.
 */
public class TokenTypeTest {

	@Test
	void testAccessTokenMatchesStandardUri() {
		Optional<TokenType> result = TokenType.from("urn:ietf:params:oauth:token-type:access_token");
		assertTrue(result.isPresent());
		assertEquals(TokenType.ACCESS_TOKEN, result.get());
	}

	@Test
	void testAccessTokenMatchesCustomUri() {
		Optional<TokenType> result = TokenType.from("urn:connellboyce:params:oauth:token-type:access_token");
		assertTrue(result.isPresent());
		assertEquals(TokenType.ACCESS_TOKEN, result.get());
	}

	@Test
	void testIdTokenMatchesStandardUri() {
		Optional<TokenType> result = TokenType.from("urn:ietf:params:oauth:token-type:id_token");
		assertTrue(result.isPresent());
		assertEquals(TokenType.ID_TOKEN, result.get());
	}

	@Test
	void testRefreshTokenMatchesStandardUri() {
		Optional<TokenType> result = TokenType.from("urn:ietf:params:oauth:token-type:refresh_token");
		assertTrue(result.isPresent());
		assertEquals(TokenType.REFRESH_TOKEN, result.get());
	}

	@Test
	void testUnknownUriReturnsEmpty() {
		Optional<TokenType> result = TokenType.from("urn:unknown:token-type");
		assertTrue(result.isEmpty());
	}

	@Test
	void testNullReturnsEmpty() {
		Optional<TokenType> result = TokenType.from(null);
		assertTrue(result.isEmpty());
	}

	@Test
	void testMatchesMethod() {
		assertTrue(TokenType.ACCESS_TOKEN.matches("urn:ietf:params:oauth:token-type:access_token"));
		assertTrue(TokenType.ACCESS_TOKEN.matches("urn:connellboyce:params:oauth:token-type:access_token"));
		assertFalse(TokenType.ACCESS_TOKEN.matches("urn:ietf:params:oauth:token-type:id_token"));
	}

	@Test
	void testGetPotentialValues() {
		assertEquals(2, TokenType.ACCESS_TOKEN.getPotentialValues().size());
		assertTrue(TokenType.ACCESS_TOKEN.getPotentialValues().contains("urn:ietf:params:oauth:token-type:access_token"));
		assertTrue(TokenType.ACCESS_TOKEN.getPotentialValues().contains("urn:connellboyce:params:oauth:token-type:access_token"));
	}
}
