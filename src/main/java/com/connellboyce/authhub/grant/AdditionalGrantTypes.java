package com.connellboyce.authhub.grant;

/**
 * Additional OAuth 2.0 grant types not included in the standard specification.
 * Includes Token Exchange (RFC 8693) and CIBA.
 */
public final class AdditionalGrantTypes {
	/**
	 * Token Exchange grant type as defined in RFC 8693.
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693">RFC 8693</a>
	 */
	public static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
	
	/**
	 * Client-Initiated Backchannel Authentication (CIBA) grant type.
	 */
	public static final String CIBA = "urn:openid:params:grant-type:ciba";

	private AdditionalGrantTypes() {
		// Utility class - prevent instantiation
	}
}
