package io.imulab.nix.oauth

import io.imulab.nix.oauth.validation.OAuthClientAuthenticationMethodValidator
import java.time.Duration

/**
 * Global server configuration data.
 */
interface OAuthContext {
    /**
     * Issuer identifier URL for the server. It will be used as the issuer for tokens
     * as well as the expected audience for most token verifications.
     */
    val issuerUrl: String

    /**
     * Absolute URL for OAuthConfig authorize endpoint
     */
    val authorizeEndpointUrl: String

    /**
     * Absolute URL for OAuthConfig token endpoint
     */
    val tokenEndpointUrl: String

    /**
     * The fallback client authentication method deployed at the token endpoint. Suggested
     * value is client_secret_basic or client_secret_post. This value can be override at
     * client authenticators, which is useful for scenarios that authentication method
     * is registered with individual clients (Open ID Connect Dynamic Client).
     */
    val defaultTokenEndpointAuthenticationMethod: String

    /**
     * Time to live for the authorization code. Suggested value is 10 minutes.
     */
    val authorizeCodeLifespan: Duration

    /**
     * Time to live for access token. Suggested value is 1 hour.
     */
    val accessTokenLifespan: Duration

    /**
     * Time to live for refresh token. Suggested value is 14 days.
     */
    val refreshTokenLifespan: Duration

    /**
     * Minimum length for the state parameter.
     */
    val stateEntropy: Int

    /**
     * Validate the configured values
     */
    fun validate() {
        check(issuerUrl.isNotEmpty()) { "issuerUrl must be set." }

        check(authorizeEndpointUrl.isNotEmpty()) { "authorizeEndpointUrl must be set." }

        check(tokenEndpointUrl.isNotEmpty()) { "tokenEndpointUrl must be set." }

        check(defaultTokenEndpointAuthenticationMethod.isNotEmpty()) {
            "defaultTokenEndpointAuthenticationMethod must be set"
        }
        OAuthClientAuthenticationMethodValidator.validate(defaultTokenEndpointAuthenticationMethod)

        check(!authorizeCodeLifespan.isZero) { "authorizeCodeLifespan must not be zero." }

        check(!accessTokenLifespan.isZero) { "accessTokenLifespan must not be zero." }

        check(!refreshTokenLifespan.isZero) { "refreshTokenLifespan must not be zero." }

        check(stateEntropy >= 0) { "state entropy must not be negative." }
    }
}