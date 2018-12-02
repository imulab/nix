package io.imulab.nix.server.authz.consent.session

/**
 * Interface for managing consent sessions.
 */
interface ConsentSessionStrategy {

    suspend fun retrieveConsent(call: Any): ConsentSession?

    suspend fun writeConsent(call: Any, session: ConsentSession)
}