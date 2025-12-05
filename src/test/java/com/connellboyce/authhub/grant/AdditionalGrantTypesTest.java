package com.connellboyce.authhub.grant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AdditionalGrantTypes constants.
 */
public class AdditionalGrantTypesTest {

	@Test
	void testTokenExchangeGrantType() {
		assertEquals("urn:ietf:params:oauth:grant-type:token-exchange", AdditionalGrantTypes.TOKEN_EXCHANGE);
	}

	@Test
	void testCibaGrantType() {
		assertEquals("urn:openid:params:grant-type:ciba", AdditionalGrantTypes.CIBA);
	}

	@Test
	void testGrantTypesAreNotEqual() {
		assertNotEquals(AdditionalGrantTypes.TOKEN_EXCHANGE, AdditionalGrantTypes.CIBA);
	}
}
