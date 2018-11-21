package io.imulab.nix.user.auth

import io.ktor.application.ApplicationCall

/**
 * Implementation of [AuthenticationFilter] that attempts to resolve [Authentication] from the request itself.
 */
class RequestAuthenticationFilter(override var next: AuthenticationFilter? = null): AuthenticationFilter {

    override suspend fun acquireAuthentication(call: ApplicationCall): Authentication {
        // TODO
        return next?.acquireAuthentication(call) ?: TODO("failed to acquire authentication")
    }
}