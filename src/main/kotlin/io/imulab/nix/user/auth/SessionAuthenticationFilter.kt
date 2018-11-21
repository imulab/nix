package io.imulab.nix.user.auth

import io.ktor.application.ApplicationCall

/**
 * Implementation of [AuthenticationFilter] to find a still-valid authentication from user's browser cookie.
 */
class SessionAuthenticationFilter(
    override var next: AuthenticationFilter? = null
) : AuthenticationFilter {

    override suspend fun acquireAuthentication(call: ApplicationCall): Authentication {

        return next?.acquireAuthentication(call) ?: TODO("failed to acquire authentication")
    }
}