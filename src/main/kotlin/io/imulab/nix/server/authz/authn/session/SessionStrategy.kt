package io.imulab.nix.server.authz.authn.session

/**
 * Interface for managing authentication sessions.
 */
interface SessionStrategy {

    suspend fun retrieve(call: Any): AuthenticationSession?

    suspend fun write(call: Any, session: AuthenticationSession)
}