package io.imulab.nix.oauth.token.storage

import io.imulab.nix.oauth.error.InvalidGrant
import io.imulab.nix.oauth.request.OAuthRequest

class MemoryAccessTokenRepository : AccessTokenRepository {

    private val db = mutableMapOf<String, OAuthRequest>()

    override suspend fun createAccessTokenSession(token: String, request: OAuthRequest) {
        db[token] = request
    }

    override suspend fun getAccessTokenSession(token: String): OAuthRequest {
        return db[token] ?: throw InvalidGrant.invalid()
    }

    override suspend fun deleteAccessTokenSession(token: String) {
        db.remove(token)
    }

    override suspend fun deleteAccessTokenAssociatedWithRequest(requestId: String) {
        val it = db.iterator()
        while (it.hasNext()) {
            val kv = it.next()
            if (kv.value.id == requestId) {
                it.remove()
                break
            }
        }
    }
}