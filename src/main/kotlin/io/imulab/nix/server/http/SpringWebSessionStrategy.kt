package io.imulab.nix.server.http

import io.imulab.nix.server.authz.authn.session.AuthenticationSession
import io.imulab.nix.server.authz.authn.session.AuthenticationSessionStrategy
import io.imulab.nix.server.authz.consent.session.ConsentSession
import io.imulab.nix.server.authz.consent.session.ConsentSessionStrategy
import org.springframework.web.server.WebSession

object SpringWebSessionStrategy : AuthenticationSessionStrategy, ConsentSessionStrategy {

    private const val authentication = "authentication"
    private const val consent = "consent"

    override suspend fun retrieveAuthentication(call: Any): AuthenticationSession? {
        return (call as? WebSession)?.getAttribute(authentication)
    }

    override suspend fun writeAuthentication(call: Any, session: AuthenticationSession) {
        (call as? WebSession)?.attributes?.put(authentication, session)
    }

    override suspend fun retrieveConsent(call: Any): ConsentSession? {
        return (call as? WebSession)?.getAttribute(consent)
    }

    override suspend fun writeConsent(call: Any, session: ConsentSession) {
        (call as? WebSession)?.attributes?.put(consent, session)
    }
}