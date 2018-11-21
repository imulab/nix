package io.imulab.nix.user.auth

import io.ktor.application.ApplicationCall

interface AuthenticationFilter {

    var next: AuthenticationFilter?

    /**
     * Convenience method to chain a list of filters together
     */
    fun setNext(next: AuthenticationFilter): AuthenticationFilter {
        this.next = next
        return next
    }

    /**
     * Acquire user authentication.
     */
    // TODO might add signature
    suspend fun acquireAuthentication(call: ApplicationCall): Authentication
}