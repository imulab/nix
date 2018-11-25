package deprecated.oauth.token.storage

import deprecated.constant.Error
import deprecated.oauth.request.OAuthRequest
import deprecated.oauth.request.OidcRequest
import deprecated.oauth.token.Token
import deprecated.oauth.token.TokenType
import java.time.LocalDateTime

class MemoryStorage:
    AuthorizeCodeStorage,
    RefreshTokenStorage,
    AccessTokenStorage,
    OpenIdConnectRequestStorage,
    TokenRevocationStorage,
    PkceStorage {

    //region Implementation for AuthorizeCodeStorage
    private val authorizeCodeDatabase = mutableMapOf<String, TokenToRequest>()

    override suspend fun createAuthorizeCodeSession(code: Token, request: OAuthRequest) {
        authorizeCodeDatabase[code.value] = TokenToRequest(code, request)
    }

    override suspend fun getAuthorizeCodeSession(code: Token): OAuthRequest {
        return authorizeCodeDatabase[code.value]?.let {
            when {
                !it.isActive -> throw Error.AuthorizeCode.inactive()
                it.request.session.hasExpired(TokenType.AuthorizeCode) -> throw Error.AuthorizeCode.expired()
                else -> it
            }
        }?.request ?: throw Error.AuthorizeCode.notFound()
    }

    override suspend fun invalidateAuthorizeCodeSession(code: Token) {
        authorizeCodeDatabase[code.value]?.isActive = false
    }
    //endregion

    //region Implementation for RefreshTokenStorage
    private val refreshTokenDatabase = mutableMapOf<String, TokenToRequest>()

    override suspend fun createRefreshTokenSession(token: Token, request: OAuthRequest) {
        TokenToRequest(token, request).let {
            refreshTokenDatabase[token.value] = it
            revocationRefreshTokenDatabase[request.id] = it
        }
    }

    override suspend fun getRefreshTokenSession(token: Token): OAuthRequest {
        return refreshTokenDatabase[token.value]?.let {
            when {
                !it.isActive -> throw Error.RefreshToken.inactive()
                it.request.session.hasExpired(TokenType.RefreshToken) -> throw Error.RefreshToken.expired()
                else -> it
            }
        }?.request ?: throw Error.RefreshToken.notFound()
    }

    override suspend fun deleteRefreshTokenSession(token: Token) {
        refreshTokenDatabase.remove(token.value)
    }
    //endregion

    //region Implementation for AccessTokenStorage
    private val accessTokenDatabase = mutableMapOf<String, TokenToRequest>()

    override suspend fun createAccessTokenSession(token: Token, request: OAuthRequest) {
        TokenToRequest(token, request).let {
            accessTokenDatabase[token.value] = it
            revocationAccessTokenDatabase[request.id] = it
        }
    }

    override suspend fun getAccessTokenSession(token: Token): OAuthRequest {
        return accessTokenDatabase[token.value]?.let {
            when {
                !it.isActive -> throw Error.AccessToken.inactive()
                it.request.session.hasExpired(TokenType.AccessToken) -> throw Error.AccessToken.expired()
                else -> it
            }
        }?.request ?: throw Error.AccessToken.notFound()
    }

    override suspend fun deleteAccessTokenSession(token: Token) {
        accessTokenDatabase.remove(token.value)
    }
    //endregion

    //region Implementation for OpenIdConnectRequestStorage
    private val oidcRequestDatabase = mutableMapOf<String, TokenToRequest>()

    override suspend fun createOidcSession(authorizeCode: Token, request: OidcRequest) {
        oidcRequestDatabase[authorizeCode.value] =
                TokenToRequest(authorizeCode, request)
    }

    override suspend fun getOidcSession(authorizeCode: Token): OidcRequest {
        return oidcRequestDatabase[authorizeCode.value]?.request as? OidcRequest
            ?: throw Error.AuthorizeCode.notFound()
    }

    override suspend fun deleteOidcSession(authorizeCode: Token) {
        oidcRequestDatabase.remove(authorizeCode.value)
    }
    //endregion

    //region Implementation for TokenRevocationStorage
    private val revocationRefreshTokenDatabase = mutableMapOf<String, TokenToRequest>()
    private val revocationAccessTokenDatabase = mutableMapOf<String, TokenToRequest>()

    override suspend fun revokeRefreshToken(requestId: String) {
        revocationRefreshTokenDatabase[requestId]?.let { deleteRefreshTokenSession(it.token) }
        revocationRefreshTokenDatabase.remove(requestId)
    }

    override suspend fun revokeAccessToken(requestId: String) {
        revocationAccessTokenDatabase[requestId]?.let { deleteAccessTokenSession(it.token) }
        revocationAccessTokenDatabase.remove(requestId)
    }
    //endregion

    //region Implementation for PkceStorage
    private val pkceDatabase = mutableMapOf<String, TokenToRequest>()

    override fun getPkceSession(authorizeCode: Token): OAuthRequest {
        return pkceDatabase[authorizeCode.value]?.request
            ?: throw Error.AuthorizeCode.notFound()
    }

    override fun createPkceSession(authorizeCode: Token, request: OAuthRequest) {
        pkceDatabase[authorizeCode.value] =
                TokenToRequest(authorizeCode, request)
    }

    override fun deletePkceSession(authorizeCode: Token) {
        pkceDatabase.remove(authorizeCode.value)
    }
    //endregion

    private class TokenToRequest(val token: Token, val request: OAuthRequest, var isActive: Boolean = true)

    fun resetAuthorizeCodeStorage() {
        this.authorizeCodeDatabase.clear()
        this.pkceDatabase.clear()
    }

    fun resetRefreshTokenStorage() {
        this.refreshTokenDatabase.clear()
        this.revocationRefreshTokenDatabase.clear()
    }

    fun resetAccessTokenStorage() {
        this.accessTokenDatabase.clear()
        this.revocationAccessTokenDatabase.clear()
    }

    fun resetOidcRequestStorage() {
        this.oidcRequestDatabase.clear()
    }

    fun reset() {
        this.resetAccessTokenStorage()
        this.resetRefreshTokenStorage()
        this.resetOidcRequestStorage()
        this.resetAuthorizeCodeStorage()
    }

    fun expireAuthorizeCode(value: String) {
        listOf(
            this.authorizeCodeDatabase[value],
            this.oidcRequestDatabase[value],
            this.pkceDatabase[value]
        ).map { tor ->
            tor?.request?.session?.let {
                it.expiry[TokenType.AuthorizeCode] = LocalDateTime.now().minusHours(1)
            }
        }
    }
}