package io.imulab.nix.server.authz.authn

import io.imulab.nix.oauth.error.AccessDenied
import io.imulab.nix.oauth.assertType
import io.imulab.nix.oidc.*
import io.imulab.nix.server.authz.authn.session.AuthenticationSession
import io.imulab.nix.server.authz.authn.session.SessionStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.lang.Exception
import java.time.LocalDateTime

/**
 * Implementation of [AuthenticationHandler] that handles the login flow re-entry logic.
 *
 * It parses the `login_token` parameter and sets the request session `subject` to the token's `sub` claim and the
 * request session `auth_time` to the token's `iat` claim.
 *
 * If the `login_token` is invalid, an access_denied error is raised.
 *
 * If the `login_token` contains a `remember` claim, this handler will write the authentication session information
 * to session repository and set the expiry for that number of seconds.
 */
class LoginTokenAuthenticationHandler(
    private val loginTokenStrategy: LoginTokenStrategy,
    private val sessionStrategy: SessionStrategy
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

        if (loginClaims.hasClaim(LoginTokenClaim.remember)) {
            val rememberForSeconds = loginClaims.getStringClaimValue(LoginTokenClaim.remember).toLongOrNull() ?: 0
            if (rememberForSeconds > 0) {
                withContext(Dispatchers.IO) {
                    launch {
                        sessionStrategy.write(rawCall, AuthenticationSession(
                            subject = loginClaims.subject,
                            authTime = loginClaims.issuedAt.toLocalDateTime(),
                            expiry = LocalDateTime.now().plusSeconds(rememberForSeconds)
                        ))
                    }
                }
            }
        }
    }
}