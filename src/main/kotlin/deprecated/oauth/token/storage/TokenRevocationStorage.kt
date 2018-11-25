package deprecated.oauth.token.storage

interface TokenRevocationStorage {

    suspend fun revokeRefreshToken(requestId: String)

    suspend fun revokeAccessToken(requestId: String)

    suspend fun revokeAll(requestId: String) {
        revokeAccessToken(requestId)
        revokeRefreshToken(requestId)
    }
}