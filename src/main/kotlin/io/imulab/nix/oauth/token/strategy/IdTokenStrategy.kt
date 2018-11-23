package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.oauth.request.OidcRequest
import io.imulab.nix.oauth.token.Token
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.GlobalScope

/**
 * Strategy for Open ID Connect id_token.
 */
interface IdTokenStrategy {

    /**
     * Generate a new Open ID Connect id_token.
     */
    suspend fun generateIdToken(request: OidcRequest, coroutineScope: CoroutineScope = GlobalScope): Token
}