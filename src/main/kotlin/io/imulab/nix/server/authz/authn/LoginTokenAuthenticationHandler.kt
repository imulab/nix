package io.imulab.nix.server.authz.authn

import io.imulab.nix.oauth.AccessDenied
import io.imulab.nix.oauth.assertType
import io.imulab.nix.oidc.OidcAuthorizeRequest
import io.imulab.nix.oidc.OidcRequestForm
import io.imulab.nix.oidc.OidcSession
import io.imulab.nix.oidc.toLocalDateTime
import io.imulab.nix.server.authz.LoginTokenStrategy
import java.lang.Exception

/**
 * Implementation of [AuthenticationHandler] that handles the login flow re-entry logic.
 *
 * It parses the `login_token` parameter and sets the request session `subject` to the token's `sub` claim and the
 * request session `auth_time` to the token's `iat` claim.
 *
 * If the `login_token` is invalid, an access_denied error is raised.
 */
class LoginTokenAuthenticationHandler(
    private val loginTokenStrategy: LoginTokenStrategy
) : AuthenticationHandler {

    override suspend fun attemptAuthenticate(form: OidcRequestForm, request: OidcAuthorizeRequest, rawCall: Any) {
        if (form.loginToken.isEmpty())
            return

        checkNotNull(request.session.assertType<OidcSession>().originalRequestTime) {
            "Original request should have been revived at this point."
        }

        val loginClaims = try {
            loginTokenStrategy.decodeLoginTokenResponse(form.loginToken)
        } catch (e: Exception) {
            throw AccessDenied.byServer("Login token is invalid.")
        }

        with(request.session.assertType<OidcSession>()) {
            subject = loginClaims.subject
            authTime = loginClaims.issuedAt.toLocalDateTime()
        }
    }
}