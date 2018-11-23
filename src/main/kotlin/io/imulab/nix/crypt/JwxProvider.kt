package io.imulab.nix.crypt

import io.imulab.nix.client.OidcClient
import io.imulab.nix.crypt.alg.EncryptionAlgorithm
import io.imulab.nix.crypt.alg.KeyManagementAlgorithm
import io.imulab.nix.crypt.alg.SigningAlgorithm
import io.imulab.nix.error.JwkException.Companion.JwkSeekException
import io.imulab.nix.support.findKeyForJweKeyManagement
import io.imulab.nix.support.findKeyForSignature
import io.imulab.nix.support.resolvePrivateKey
import io.imulab.nix.support.resolvePublicKey
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType.WHITELIST
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.consumer.JwtContext
import java.security.Key

class JwxProvider {

    // kty, kid is set with headers
    fun generateJsonWebToken(
        claims: JwtClaims,
        headers: Map<String, String> = emptyMap(),
        signingAlgorithm: SigningAlgorithm,
        jwks: JsonWebKeySet
    ): String {
        val jwk = jwks.findKeyForSignature(signingAlgorithm)

        return JsonWebSignature().also { jws ->
            jws.keyIdHeaderValue = jwk.keyId
            jws.algorithmHeaderValue = jwk.algorithm
            headers.forEach { t, u -> jws.setHeader(t, u) }
            jws.payload = claims.toJson()
            jws.key = jwk.resolvePrivateKey()
        }.compactSerialization
    }

    fun decodeIdJsonWebToken(
        jwt: String,
        jwks: JsonWebKeySet,
        client: OidcClient,
        extraCriteria: (JwtConsumerBuilder) -> Unit = {}
    ): JwtContext {
        val jwk = jwks.findJsonWebKey(
            null,
            client.idTokenSignedResponseAlgorithm.keyType,
            Use.SIGNATURE,
            client.idTokenSignedResponseAlgorithm.alg) ?: throw JwkSeekException()
        return decodeJsonWebToken(jwt, client.idTokenSignedResponseAlgorithm, jwk.key, extraCriteria)
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
        jwks: JsonWebKeySet,
        keyAlg: KeyManagementAlgorithm,
        encAlg: EncryptionAlgorithm
    ): String {
        val jwk = jwks.findKeyForJweKeyManagement(keyAlg)

        return JsonWebEncryption().also { jwe ->
            jwe.setPlaintext(payload)
            jwe.encryptionMethodHeaderParameter = encAlg.alg
            jwe.algorithmHeaderValue = keyAlg.identifier
            jwe.contentTypeHeaderValue = "JWT"
            jwe.key = jwk.resolvePublicKey()
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