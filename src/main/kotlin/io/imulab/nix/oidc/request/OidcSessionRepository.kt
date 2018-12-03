package io.imulab.nix.oidc.request

interface OidcSessionRepository {

    /**
     * Stores OIDC request for the given [authorizeCode].
     */
    suspend fun createOidcSession(authorizeCode: String, session: OidcSession)

    /**
     * Retrieve OIDC request session given [authorizeCode].
     */
    suspend fun getOidcSession(authorizeCode: String): OidcSession

    /**
     * Delete the OIDC request session associated with the [authorizeCode].
     */
    suspend fun deleteOidcSession(authorizeCode: String)
}