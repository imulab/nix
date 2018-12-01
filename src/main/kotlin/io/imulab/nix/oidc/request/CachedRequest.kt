package io.imulab.nix.oidc.request

import java.time.LocalDateTime

/**
 * Data object of a server cached request object. This can be created when client
 * registers a set of request_uris as well as when server actively fetches content
 * from a request_uri during request.
 */
class CachedRequest(

    /**
     * Original request_uri parameter used to fetch this request, less any fragment component.
     */
    val requestUri: String,

    /**
     * Fetched request object.
     */
    val request: String,

    /**
     * When this cached request expire.
     */
    val expiry: LocalDateTime? = null,

    /**
     * Computed SHA-256 hash of the [request].
     */
    val hash: String = ""
) {
    fun hasExpired(): Boolean = expiry?.isAfter(LocalDateTime.now()) == true
}