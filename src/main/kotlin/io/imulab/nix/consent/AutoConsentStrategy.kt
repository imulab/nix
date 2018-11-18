package io.imulab.nix.consent

import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.spi.http.HttpRequestReader

/**
 * Implementation for [ConsentStrategy] which automatically grants all requested scope without actually
 * asking permission from the user. This implementation is only intended for development or debugging.
 */
object AutoConsentStrategy : ConsentStrategy {

    override fun acquireConsent(httpRequest: HttpRequestReader, authorizeRequest: AuthorizeRequest) {
        authorizeRequest.getRequestScopes().forEach { scope ->
            authorizeRequest.grantScope(scope)
        }
        authorizeRequest.setSession(DefaultJwtSession.Builder().also {
            it.subject = "davidiamyou@gmail.com"
            it.getClaims().setGeneratedJwtId()
            it.getClaims().subject = "davidiamyou@gmail.com"
        }.build())
    }
}