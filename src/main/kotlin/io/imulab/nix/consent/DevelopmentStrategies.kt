package io.imulab.nix.consent

import io.imulab.astrea.domain.extension.minusSeconds
import io.imulab.astrea.domain.extension.setAuthTime
import io.imulab.astrea.domain.extension.setRequestAtTime
import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.domain.session.impl.DefaultOidcSession
import io.imulab.astrea.spi.http.HttpRequestReader
import org.jose4j.jwt.NumericDate

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

object OidcConsentStrategy: ConsentStrategy {

    override fun acquireConsent(httpRequest: HttpRequestReader, authorizeRequest: AuthorizeRequest) {
        authorizeRequest.getRequestScopes().forEach { scope ->
            authorizeRequest.grantScope(scope)
        }
        authorizeRequest.setSession(DefaultOidcSession.Builder().also {
            it.subject = "davidiamyou@gmail.com"
            with(it.getClaims()) {
                setGeneratedJwtId()
                subject = "davidiamyou@gmail.com"
                setAuthTime(NumericDate.now().minusSeconds(10))
                setRequestAtTime(NumericDate.now().minusSeconds(20))
            }
            it.getClaims().setGeneratedJwtId()
            it.getClaims().subject = "davidiamyou@gmail.com"
            it.getClaims()
        }.build())
    }
}