package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.token.Token

interface PkceStorage {

    /**
     * Returns a [OAuthRequest] if it was associated with the [authorizeCode]. This storage will only
     * check for existence, as expiration and other checks should have been performed by an upstream
     * [AuthorizeCodeStorage] when chained.
     */
    fun getPkceSession(authorizeCode: Token): OAuthRequest

    /**
     * Associates the given [authorizeCode] with the [request]. The saved [request] needs to be
     * [OAuthRequest.sanitize] first.
     */
    fun createPkceSession(authorizeCode: Token, request: OAuthRequest)

    /**
     * Removes the associated [OAuthRequest] by [authorizeCode]
     */
    fun deletePkceSession(authorizeCode: Token)
}