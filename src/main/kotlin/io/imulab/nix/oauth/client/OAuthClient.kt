package io.imulab.nix.oauth.client

import io.imulab.nix.oauth.*

interface OAuthClient {

    /**
     * Identifier for the client
     */
    val id: String

    /**
     * (Hashed) secret for the client
     */
    val secret: ByteArray

    /**
     * Name of the client, represented to the end user.
     */
    val name: String

    /**
     * Type of the client. Public clients may have an empty [secret].
     */
    val type: String

    /**
     * List of pre-registered and pre-validated redirect_uri. These values will be
     * consumed with the assumption that they are valid.
     */
    val redirectUris: Set<String>

    /**
     * Supported response_type for this client. Any request made with
     * response_type outside these values shall be rejected unsupported_response_type.
     */
    val responseTypes: Set<String>

    /**
     * Supported grant_type for this client. Any request made with
     * grant_type outside these values shall be rejected with unsupported_grant_type.
     */
    val grantTypes: Set<String>

    /**
     * Supported scope for this client. Any request made with scope
     * outside these values shall be rejected with invalid_scope.
     */
    val scopes: Set<String>

    /**
     * Utility method to ensure this client possesses the [presented] grant_type
     * value. It it does not, a unsupported_grant_type error is raised.
     */
    fun mustGrantType(presented: String): String {
        if (!this.grantTypes.contains(presented))
            throw UnsupportedGrantType.unsupported(presented)
        return presented
    }

    /**
     * Utility method to ensure this client can request the [presented] scope
     * value. It it cannot, a invalid_scope error is raised.
     */
    fun mustScope(presented: String): String {
        if (!this.scopes.contains(presented))
            throw InvalidScope.unknown(presented)
        return presented
    }

    /**
     * Utility method to select a redirect uri from options:
     * - if one is [presented], it must match one of the registered redirect_uri value, if any.
     * - if one is not presented, there must be exactly one registered redirect_uri.
     */
    fun determineRedirectUri(presented: String): String {
        return if (presented.isBlank()) {
            when {
                redirectUris.size == 1 -> redirectUris.first()
                else -> throw InvalidRequest.indetermined(Param.redirectUri)
            }
        } else {
            when {
                redirectUris.contains(presented) -> presented
                else -> throw InvalidRequest.indetermined(Param.redirectUri)
            }
        }
    }
}