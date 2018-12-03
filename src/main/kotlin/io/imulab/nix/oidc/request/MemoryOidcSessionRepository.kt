package io.imulab.nix.oidc.request

import io.imulab.nix.oauth.error.InvalidGrant

class MemoryOidcSessionRepository : OidcSessionRepository {

    private val db = mutableMapOf<String, OidcSession>()

    override suspend fun createOidcSession(authorizeCode: String, session: OidcSession) {
        db[authorizeCode] = session
    }

    override suspend fun getOidcSession(authorizeCode: String): OidcSession {
        return db[authorizeCode] ?: throw InvalidGrant.invalid()
    }

    override suspend fun deleteOidcSession(authorizeCode: String) {
        db.remove(authorizeCode)
    }
}