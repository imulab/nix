package deprecated.user.auth

import io.ktor.application.ApplicationCall

/**
 * Implementation of [AuthenticationFilter] that redirects user to external authentication system.
 */
class RedirectAuthenticationFilter : AuthenticationFilter {

    // This is the last resort. Ignore attempts to chain more filters.
    override var next: AuthenticationFilter?
        get() = null
        set(_) {}

    override suspend fun acquireAuthentication(call: ApplicationCall): Authentication {
        // TODO perform redirection and throw special exception
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}