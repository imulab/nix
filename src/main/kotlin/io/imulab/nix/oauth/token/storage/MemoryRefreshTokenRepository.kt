package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.error.InvalidGrant
import io.imulab.nix.oauth.request.OAuthRequest

class MemoryRefreshTokenRepository : RefreshTokenRepository {

    private val db = mutableMapOf<String, OAuthRequest>()

    override suspend fun createRefreshTokenSession(token: String, request: OAuthRequest) {
        db[token] = request
    }

    override suspend fun getRefreshTokenSession(token: String): OAuthRequest {
        return db[token] ?: throw InvalidGrant.invalid()
    }

    override suspend fun deleteRefreshTokenSession(token: String) {
        db.remove(token)
    }
}