package io.imulab.nix.server.authz.authn.session

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
 * Implementation of [SessionStrategy] to use the session feature of the Ktor framework to manage
 * [AuthenticationSession].
 */
object KtorSessionStrategy : SessionStrategy {

    override suspend fun retrieve(call: Any): AuthenticationSession? {
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

    override suspend fun write(call: Any, session: AuthenticationSession) {
        check(call is ApplicationCall)
        call.sessions.set(session)
    }
}