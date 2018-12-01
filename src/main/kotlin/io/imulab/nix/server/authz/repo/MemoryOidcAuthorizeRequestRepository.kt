package io.imulab.nix.server.authz.repo

import io.imulab.nix.oidc.request.OidcAuthorizeRequest

/**
 * Memory implementation for [OidcAuthorizeRequestRepository]. This implementation is intended for
 * development and/or testing purposes only. It does not follow the interface guideline to utilize
 * a time-to-live configuration. It does not utilize the nonce. It is not thread-safe either.
 */
class MemoryOidcAuthorizeRequestRepository : OidcAuthorizeRequestRepository {

    private val db = mutableMapOf<String, OidcAuthorizeRequest>()

    override suspend fun save(request: OidcAuthorizeRequest, nonce: String) {
        db[request.id] = request
    }

    override suspend fun get(requestId: String, nonce: String): OidcAuthorizeRequest? = db[requestId]

    override suspend fun delete(requestId: String) {
        db.remove(requestId)
    }
}