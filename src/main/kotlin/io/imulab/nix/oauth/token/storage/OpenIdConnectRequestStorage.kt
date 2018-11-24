package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.request.OidcRequest
import io.imulab.nix.oauth.token.Token

interface OpenIdConnectRequestStorage {

    /**
     * Stores OIDC request for the given [authorizeCode].
     */
    suspend fun createOidcSession(authorizeCode: Token, request: OidcRequest)

    /**
     * Retrieve OIDC request given [authorizeCode].
     */
    suspend fun getOidcSession(authorizeCode: Token): OidcRequest

    /**
     * Delete the OIDC request session associated with the [authorizeCode].
     */
    suspend fun deleteOidcSession(authorizeCode: Token)
}