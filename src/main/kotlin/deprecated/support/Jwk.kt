package deprecated.support

import deprecated.constant.Error
import deprecated.crypt.alg.KeyManagementAlgorithm
import deprecated.crypt.alg.SigningAlgorithm
import org.jose4j.jwk.*
import java.security.Key

fun JsonWebKey.resolvePrivateKey(): Key = when(this) {
    is RsaJsonWebKey -> this.rsaPrivateKey
    is EllipticCurveJsonWebKey -> this.ecPrivateKey
    is PublicJsonWebKey -> this.privateKey
    else -> this.key
}

fun JsonWebKey.resolvePublicKey(): Key = when(this) {
    is RsaJsonWebKey -> this.getRsaPublicKey()
    is EllipticCurveJsonWebKey -> this.ecPublicKey
    is PublicJsonWebKey -> this.publicKey
    else -> this.key
}

fun JsonWebKeySet.findKeyForSignature(signingAlgorithm: SigningAlgorithm): JsonWebKey =
    this.findJsonWebKey(null, signingAlgorithm.keyType, Use.SIGNATURE, signingAlgorithm.alg)
        ?: this.findJsonWebKey(null, null, Use.SIGNATURE, signingAlgorithm.alg)
        ?: this.findJsonWebKey(null, signingAlgorithm.keyType, Use.SIGNATURE, null)
        ?: throw Error.Jwk.notFoundForSignature()

fun JsonWebKeySet.findKeyForJweKeyManagement(keyManagementAlgorithm: KeyManagementAlgorithm): JsonWebKey =
    this.findJsonWebKey(null, null, Use.ENCRYPTION, keyManagementAlgorithm.identifier)
        ?: throw Error.Jwk.notFoundForEncryption()