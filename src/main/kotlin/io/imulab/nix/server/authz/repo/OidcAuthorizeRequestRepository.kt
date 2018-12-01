package io.imulab.nix.server.authz.repo

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