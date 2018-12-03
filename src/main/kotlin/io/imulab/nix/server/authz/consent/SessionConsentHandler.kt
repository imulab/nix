package io.imulab.nix.server.authz.consent

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.server.authz.consent.session.ConsentSessionStrategy
import java.time.LocalDateTime

/**
 * Implementation of [ConsentHandler] that uses the session to restore consent information. The session
 * is provided via [ConsentSessionStrategy].
 *
 * When a session is successfully restored, its expiry is first checked. If it hasn't expired, this strategy
 * will grant all previously granted scopes found in the session and restore all idTokenClaims into the request session.
 */
class SessionConsentHandler(
    private val sessionStrategy: ConsentSessionStrategy
) : ConsentHandler {

    override suspend fun attemptAuthorize(form: OidcRequestForm, request: OidcAuthorizeRequest, rawCall: Any) {
        val consentSession = sessionStrategy.retrieveConsent(rawCall)
            ?.let { if (it.expiry.isBefore(LocalDateTime.now())) null else it }
            ?: return

        consentSession.grantedScopes.forEach { request.grantScope(it) }

        with(request.session.assertType<OidcSession>()) {
            idTokenClaims.putAll(consentSession.claims)
        }
    }
}