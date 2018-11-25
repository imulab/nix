package io.imulab.nix.oauth.client

import io.imulab.nix.oauth.ClientType
import io.imulab.nix.oauth.GrantType
import io.imulab.nix.oauth.ResponseType
import io.imulab.nix.oauth.UnsupportedGrantType

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
     * Type of the client. Public clients may have an empty [secret].
     */
    val type: ClientType.Value

    /**
     * List of pre-registered and pre-validated redirect_uri. These values will be
     * consumed with the assumption that they are valid.
     */
    val redirectUris: Set<String>

    /**
     * Supported response_type for this client. Any request made with
     * response_type outside these values shall be rejected unsupported_response_type.
     */
    val responseTypes: Set<ResponseType.Value>

    /**
     * Supported grant_type for this client. Any request made with
     * grant_type outside these values shall be rejected with unsupported_grant_type.
     */
    val grantTypes: Set<GrantType.Value>

    /**
     * Supported scope for this client. Any request made with scope
     * outside these values shall be rejected with invalid_scope.
     */
    val scopes: Set<String>

    /**
     * Utility method to ensure this client possesses the [presented] grant_type
     * value. It it does not, a unsupported_grant_type error is raised.
     */
    fun mustGrantType(presented: GrantType.Value): GrantType.Value {
        if (!this.grantTypes.contains(presented))
            throw UnsupportedGrantType.unsupported(presented.spec)
        return presented
    }
}