package io.imulab.nix.oidc.handler.helper

import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import java.security.MessageDigest
import java.util.*

object TokenHashHelper {

    private val sha256 = MessageDigest.getInstance("SHA-256")
    private val sha384 = MessageDigest.getInstance("SHA-384")
    private val sha512 = MessageDigest.getInstance("SHA-512")
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun leftMostHash(token: String, signingAlgorithm: JwtSigningAlgorithm): String {
        val hashed = getHasher(signingAlgorithm).digest(token.toByteArray())
        return encoder.encodeToString(hashed.copyOfRange(0, hashed.size/2))
    }

    private fun getHasher(signingAlgorithm: JwtSigningAlgorithm): MessageDigest {
        return when (signingAlgorithm) {
            JwtSigningAlgorithm.HS256,
            JwtSigningAlgorithm.RS256,
            JwtSigningAlgorithm.ES256 -> sha256
            JwtSigningAlgorithm.HS384,
            JwtSigningAlgorithm.RS384,
            JwtSigningAlgorithm.ES384 -> sha384
            JwtSigningAlgorithm.HS512,
            JwtSigningAlgorithm.RS512,
            JwtSigningAlgorithm.ES512 -> sha512
            else -> throw IllegalArgumentException("Algorithm ${signingAlgorithm.spec} does not support hashing.")
        }
    }
}