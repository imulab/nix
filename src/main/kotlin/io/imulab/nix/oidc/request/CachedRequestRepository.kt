package io.imulab.nix.oidc.request

/**
 * Data management interface for a [CachedRequest].
 */
interface CachedRequestRepository {

    /**
     * Write a [request] to cache. Implementations may expect [CachedRequest.expiry] if
     * it is set.
     */
    suspend fun write(request: CachedRequest)

    /**
     * Find if a [CachedRequest] was cached with [requestUri].
     *
     * @param requestUri the unmodified version of the request_uri parameter, including
     * scheme, host and fragment (if any).
     */
    suspend fun find(requestUri: String): CachedRequest?

    /**
     * Remove the cached entry associated with [requestUri].
     */
    suspend fun evict(requestUri: String)
}