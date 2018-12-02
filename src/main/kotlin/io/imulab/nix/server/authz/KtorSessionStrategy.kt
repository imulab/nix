package io.imulab.nix.server.authz

import io.imulab.nix.server.authz.authn.session.AuthenticationSession
import io.imulab.nix.server.authz.authn.session.AuthenticationSessionStrategy
import io.imulab.nix.server.authz.consent.session.ConsentSession
import io.imulab.nix.server.authz.consent.session.ConsentSessionStrategy
import io.ktor.application.ApplicationCall
import io.ktor.sessions.clear
import io.ktor.sessions.get
import io.ktor.sessions.sessions
import io.ktor.sessions.set
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDateTime

/**
 * Implementation of [AuthenticationSessionStrategy] to use the session feature of the Ktor framework to manage
 * [AuthenticationSession].
 */
object KtorSessionStrategy : AuthenticationSessionStrategy, ConsentSessionStrategy {

    override suspend fun retrieveAuthentication(call: Any): AuthenticationSession? {
        check(call is ApplicationCall)
        return call.sessions.get<AuthenticationSession>()?.let {
            if (it.expiry.isBefore(LocalDateTime.now())) {
                withContext(Dispatchers.IO) {
                    launch { call.sessions.clear<AuthenticationSession>() }
                }
                null
            } else it
        }
    }

    override suspend fun writeAuthentication(call: Any, session: AuthenticationSession) {
        check(call is ApplicationCall)
        call.sessions.set(session)
    }

    override suspend fun retrieveConsent(call: Any): ConsentSession? {
        check(call is ApplicationCall)
        return call.sessions.get<ConsentSession>()?.let {
            if (it.expiry.isBefore(LocalDateTime.now())) {
                withContext(Dispatchers.IO) {
                    launch { call.sessions.clear<ConsentSession>() }
                }
                null
            } else it
        }
    }

    override suspend fun writeConsent(call: Any, session: ConsentSession) {
        check(call is ApplicationCall)
        call.sessions.set(session)
    }
}