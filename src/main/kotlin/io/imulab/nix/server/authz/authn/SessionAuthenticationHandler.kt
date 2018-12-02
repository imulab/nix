package io.imulab.nix.server.authz.authn

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.server.authz.authn.session.AuthenticationSessionStrategy
import io.ktor.application.ApplicationCall
import java.time.LocalDateTime

/**
 * Implementation of [AuthenticationHandler] that uses the session to restore authentication information. The session
 * is provided via [AuthenticationSessionStrategy].
 *
 * When a session is successfully restored, its expiry is first checked. If a max age property is provided (either
 * directly through request or through [OidcClient.defaultMaxAge]), session auth_time is also ensured to have not
 * exceed the limit.
 *
 * If all conditions are met, request session is set. Else, handler simply returns.
 */
class SessionAuthenticationHandler(
    private val sessionStrategy: AuthenticationSessionStrategy
) : AuthenticationHandler {

    override suspend fun attemptAuthenticate(form: OidcRequestForm, request: OidcAuthorizeRequest, rawCall: Any) {
        check(rawCall is ApplicationCall)

        val authSession = sessionStrategy.retrieveAuthentication(rawCall)
            ?.let { if (it.expiry.isBefore(LocalDateTime.now())) null else it }
            ?: return
        val maxAge = if (request.maxAge > 0) request.maxAge else
            request.client.assertType<OidcClient>().defaultMaxAge
        if (maxAge > 0 && authSession.authTime.plusSeconds(maxAge).isBefore(LocalDateTime.now()))
            return

        with(request.session.assertType<OidcSession>()) {
            subject = authSession.subject
            authTime = authSession.authTime
        }
    }
}