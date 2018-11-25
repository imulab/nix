package deprecated.oauth.token.strategy

import deprecated.constant.Error
import deprecated.crypt.alg.SigningAlgorithm
import deprecated.oauth.request.OAuthRequest
import deprecated.oauth.token.SignedToken
import deprecated.oauth.token.Token
import deprecated.oauth.token.TokenType
import java.security.Key

interface RefreshTokenStrategy {

    fun fromRaw(raw: String): Token

    fun generateToken(request: OAuthRequest): Token

    fun verifyToken(request: OAuthRequest, token: String): Token
}

class HmacRefreshTokenStrategy(key: Key, signingAlgorithm: SigningAlgorithm, codeLength: Int = 32):
    HmacBaseStrategy(key, signingAlgorithm, codeLength),
    RefreshTokenStrategy {

    override fun createToken(value: String, signature: String): Token =
        SignedToken(TokenType.RefreshToken, value, signature)

    override fun badSignatureException(): Throwable = Error.RefreshToken.badSignature()

    override fun badFormatException(): Throwable = Error.RefreshToken.badFormat()

    override fun fromRaw(raw: String): Token = createFromRaw(raw)

    override fun generateToken(request: OAuthRequest): Token = generate()

    override fun verifyToken(request: OAuthRequest, token: String): Token = verify(fromRaw(token))
}