package io.imulab.nix.server.authz.authn

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oidc.OidcAuthorizeRequest
import io.imulab.nix.oidc.OidcRequestForm
import io.imulab.nix.oidc.OidcSession
import java.time.Duration
import java.time.LocalDateTime

/**
 * Development/Test only implementation of [AuthenticationHandler]. This handler aims at logging a dummy user without
 * invoking the actual redirection logic. It only works when `prompt=none` or no `prompt` set.
 *
 * Do NOT use this in production.
 */
class AutoLoginAuthenticationHandler(
    private val autoSubject: String = "bec480a6-c2e4-4ff8-8a20-774443fd1197",
    private val authTimeLeeway: Duration = Duration.ofSeconds(5)
) : AuthenticationHandler {

    override suspend fun attemptAuthenticate(form: OidcRequestForm, request: OidcAuthorizeRequest) {
        with(request.session.assertType<OidcSession>()) {
            subject = autoSubject
            authTime = LocalDateTime.now().minus(authTimeLeeway)
        }
    }
}