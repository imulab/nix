package io.imulab.nix.server.authz.consent

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.AccessDenied
import io.imulab.nix.oauth.reserved.space
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.oidc.reserved.ConsentTokenClaim
import io.imulab.nix.server.authz.consent.session.ConsentSession
import io.imulab.nix.server.authz.consent.session.ConsentSessionStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.lang.Exception
import java.time.LocalDateTime

class ConsentTokenConsentHandler(
    private val consentTokenStrategy: ConsentTokenStrategy,
    private val sessionStrategy: ConsentSessionStrategy
) : ConsentHandler {

    override suspend fun attemptAuthorize(form: OidcRequestForm, request: OidcAuthorizeRequest, rawCall: Any) {
        if (form.consentToken.isEmpty())
            return

        checkNotNull(request.session.assertType<OidcSession>().originalRequestTime) {
            "Original request should have been revived at this point."
        }

        val consentClaims = try {
            consentTokenStrategy.decodeConsentTokenResponse(form.consentToken)
        } catch (e: Exception) {
            throw AccessDenied.byServer("Consent token is invalid.")
        }

        if (consentClaims.hasClaim(ConsentTokenClaim.scope))
            consentClaims.getStringClaimValue(ConsentTokenClaim.scope)
                .split(space)
                .filter { it.isNotBlank() }
                .forEach { request.grantScope(it) }

        // TODO check what's the map structure, and then transfer them to session.idTokenClaims

        if (consentClaims.hasClaim(ConsentTokenClaim.remember)) {
            val rememberForSeconds = consentClaims.getStringClaimValue(ConsentTokenClaim.remember).toLongOrNull() ?: 0
            if (rememberForSeconds > 0) {
                withContext(Dispatchers.IO) {
                    launch {
                        sessionStrategy.writeConsent(rawCall, ConsentSession(
                            subject = request.session.subject,
                            expiry = LocalDateTime.now().plusSeconds(rememberForSeconds),
                            grantedScopes = request.grantedScopes,
                            claims = request.session.assertType<OidcSession>().idTokenClaims.toMap()
                        ))
                    }
                }
            }
        }
    }
}