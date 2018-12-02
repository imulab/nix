package io.imulab.nix.server.authz.authn.session

/**
 * Interface for managing authentication sessions.
 */
interface AuthenticationSessionStrategy {

    suspend fun retrieveAuthentication(call: Any): AuthenticationSession?

    suspend fun writeAuthentication(call: Any, session: AuthenticationSession)
}