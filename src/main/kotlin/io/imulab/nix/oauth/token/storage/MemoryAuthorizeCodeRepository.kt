package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.error.InvalidGrant
import io.imulab.nix.oauth.request.OAuthRequest

class MemoryAuthorizeCodeRepository : AuthorizeCodeRepository {

    private val db = mutableMapOf<String, OAuthRequest>()

    override suspend fun createAuthorizeCodeSession(code: String, request: OAuthRequest) {
        db[code] = request
    }

    override suspend fun getAuthorizeCodeSession(code: String): OAuthRequest {
        return db[code] ?: throw InvalidGrant.invalid()
    }

    override suspend fun invalidateAuthorizeCodeSession(code: String) {
        db.remove(code)
    }
}