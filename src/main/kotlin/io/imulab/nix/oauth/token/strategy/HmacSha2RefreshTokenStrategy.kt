package io.imulab.nix.oauth.token.strategy

import io.imulab.nix.oauth.error.InvalidGrant
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.reserved.dot
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import org.jose4j.jca.ProviderContext
import org.jose4j.jws.HmacUsingShaAlgorithm
import java.security.Key
import java.util.*
import java.util.concurrent.ThreadLocalRandom

class HmacSha2RefreshTokenStrategy(
    private val key: Key,
    private val tokenLength: Int = 32,
    signingAlgorithm: JwtSigningAlgorithm
) : RefreshTokenStrategy {

    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()
    private val hmac = when (signingAlgorithm) {
        JwtSigningAlgorithm.HS256 -> HmacUsingShaAlgorithm.HmacSha256()
        JwtSigningAlgorithm.HS384 -> HmacUsingShaAlgorithm.HmacSha384()
        JwtSigningAlgorithm.HS512 -> HmacUsingShaAlgorithm.HmacSha512()
        else -> throw IllegalArgumentException("not an hmac-sha2 algorithm.")
    }

    override fun computeIdentifier(token: String): String {
        val parts = token.split(dot)
        if (parts.size != 2)
            throw InvalidGrant.invalid()
        return parts[1]
    }

    override suspend fun generateToken(request: OAuthRequest): String {
        val randomBytes = ByteArray(tokenLength).also { ThreadLocalRandom.current().nextBytes(it) }
        val signatureBytes = hmac.sign(key, randomBytes, ProviderContext())
        return encoder.encodeToString(randomBytes) + dot + encoder.encodeToString(signatureBytes)
    }

    override suspend fun verifyToken(token: String, request: OAuthRequest) {
        val parts = token.split(dot)
        if (parts.size != 2)
            throw InvalidGrant.invalid()

        if (!hmac.verifySignature(
                decoder.decode(parts[1]),
                key,
                decoder.decode(parts[0]),
                ProviderContext()
            )
        ) {
            throw InvalidGrant.invalid()
        }
    }
}