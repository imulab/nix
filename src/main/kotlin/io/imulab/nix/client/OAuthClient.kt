package io.imulab.nix.client

import io.imulab.nix.client.metadata.ClientType
import io.imulab.nix.client.metadata.GrantType
import io.imulab.nix.client.metadata.ResponseType
import io.imulab.nix.error.UnauthorizedClientException

interface OAuthClient {

    /**
     * REQUIRED. Globally unique id of this client.
     */
    val id: String

    /**
     * REQUIRED. Name of the client to be presented to end user.
     */
    val name: String

    /**
     * OPTIONAL. Secret of the client.
     * If the client does not require a secret (i.e. a public client), this can be set of empty byte array.
     * When the secret is stored at rest (i.e. in a database), its value must not appear in plain.
     */
    val secret: ByteArray

    /**
     * OPTIONAL. Type of this client.
     * If not specified, default to [ClientType.CONFIDENTIAL].
     */
    val type: ClientType

    /**
     * REQUIRED. Array of Redirection URI values used by the Client.
     * One of these registered Redirection URI values MUST exactly match the redirect_uri parameter value used in
     * each Authorization Request, with the matching performed as Simple String Comparison.
     */
    val redirectUris: List<String>

    /**
     * OPTIONAL. Response type of this client.
     * If not set, default to [ResponseType.Code]
     */
    val responseTypes: Set<ResponseType>

    /**
     * OPTIONAL. Grant type of this client.
     * If not set, default to [GrantType.AuthorizationCode]
     */
    val grantTypes: Set<GrantType>

    /**
     * OPTIONAL. Registered scopes allowed by this client.
     */
    val scopes: Set<String>

    /**
     * Asserts that this client has [expected] grant type. When this client does not
     * have the [expected] grant type, `[hard] == true` means it will throw exception;
     * `[hard] == false` means it will silently return result.
     */
    fun mustGrantType(expected: GrantType, hard: Boolean = true): Boolean {
        if (!grantTypes.contains(expected)) {
            if (hard)
                throw UnauthorizedClientException(expected)
            else
                return false
        }
        return true
    }
}