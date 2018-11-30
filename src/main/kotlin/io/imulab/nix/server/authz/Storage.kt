package io.imulab.nix.server.authz

import io.imulab.nix.oidc.OidcAuthorizeRequest

/**
 * Storage interface for saving an [OidcAuthorizeRequest] for re-entry.
 */
interface OidcAuthorizeRequestRepository {

    /**
     * Saves a [request]. Implementations are suggested to utilize a time-to-live strategy to evict
     * the request after a certain time. This ensures the request will not be orphaned if request
     * re-entry does not happen for some reason.
     */
    suspend fun save(request: OidcAuthorizeRequest, nonce: String)

    /**
     * Retrieves the request by its id. Implementation should return null if such request is not found.
     */
    suspend fun get(requestId: String, nonce: String): OidcAuthorizeRequest?

    /**
     * Deletes the request by its id. This usually happens after re-entry data has been processed and hence
     * no longer needs the original request in repository.
     */
    suspend fun delete(requestId: String)
}

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