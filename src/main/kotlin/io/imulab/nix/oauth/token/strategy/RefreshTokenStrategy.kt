package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.constant.Error
import io.imulab.nix.crypt.alg.SigningAlgorithm
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.token.SignedToken
import io.imulab.nix.oauth.token.Token
import io.imulab.nix.oauth.token.TokenType
import java.security.Key

interface RefreshTokenStrategy {

    fun fromRaw(raw: String): Token

    fun generateToken(request: OAuthRequest): Token

    fun verifyToken(request: OAuthRequest, token: String): Token
}

class HmacRefreshTokenStrategy(key: Key, signingAlgorithm: SigningAlgorithm, codeLength: Int = 32):
    HmacBaseStrategy(key, signingAlgorithm, codeLength), RefreshTokenStrategy {

    override fun createToken(value: String, signature: String): Token =
        SignedToken(TokenType.RefreshToken, value, signature)

    override fun badSignatureException(): Throwable = Error.RefreshToken.badSignature()

    override fun badFormatException(): Throwable = Error.RefreshToken.badFormat()

    override fun fromRaw(raw: String): Token = createFromRaw(raw)

    override fun generateToken(request: OAuthRequest): Token = generate()

    override fun verifyToken(request: OAuthRequest, token: String): Token = verify(fromRaw(token))
}