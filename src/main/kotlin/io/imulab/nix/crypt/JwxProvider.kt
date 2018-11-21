package io.imulab.nix.crypt

import io.imulab.nix.crypt.alg.EncryptionAlgorithm
import io.imulab.nix.crypt.alg.KeyManagementAlgorithm
import io.imulab.nix.crypt.alg.SigningAlgorithm
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType.WHITELIST
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.consumer.JwtContext
import java.security.Key

class JwxProvider {

    // kty, kid is set with headers
    fun generateJsonWebToken(
        claims: JwtClaims,
        headers: Map<String, String>,
        signingAlgorithm: SigningAlgorithm,
        key: Key
    ): String {
        return JsonWebSignature().also { jws ->
            headers.forEach { t, u -> jws.setHeader(t, u) }
            jws.payload = claims.toJson()
            jws.key = key
            jws.algorithmHeaderValue = signingAlgorithm.alg
        }.compactSerialization
    }

    fun decodeJsonWebToken(
        jwt: String,
        signingAlgorithm: SigningAlgorithm,
        key: Key,
        extraCriteria: (JwtConsumerBuilder) -> Unit = {}
    ): JwtContext {
        val consumer = JwtConsumerBuilder()
            .setRequireJwtId()
            .setJwsAlgorithmConstraints(AlgorithmConstraints(WHITELIST, signingAlgorithm.alg))
            .setVerificationKey(key)
            .also(extraCriteria)
            .build()
        return consumer.process(jwt)
    }

    fun generateJsonWebEncryption(
        payload: String,
        key: Key,
        keyAlg: KeyManagementAlgorithm,
        encAlg: EncryptionAlgorithm
    ): String {
        return JsonWebEncryption().also { jwe ->
            jwe.setPlaintext(payload)
            jwe.encryptionMethodHeaderParameter = encAlg.alg
            jwe.algorithmHeaderValue = keyAlg.identifier
            jwe.key = key
        }.compactSerialization
    }

    fun decryptJsonWebEncryption(
        encrypted: String,
        key: Key,
        keyAlg: KeyManagementAlgorithm,
        encAlg: EncryptionAlgorithm
    ): String {
        return JsonWebEncryption().also { jwe ->
            jwe.setAlgorithmConstraints(AlgorithmConstraints(WHITELIST, keyAlg.identifier))
            jwe.setContentEncryptionAlgorithmConstraints(AlgorithmConstraints(WHITELIST, encAlg.alg))
            jwe.compactSerialization = encrypted
            jwe.key = key
        }.plaintextString
    }
}