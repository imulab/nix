package io.imulab.nix.oidc.jwk

import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import org.jose4j.jwk.*
import java.security.Key

/**
 * Resolves the private key of the json web key for signing and decryption.
 * If [this] is a symmetric key (octet-sequence), returns the key directly.
 */
fun JsonWebKey.resolvePrivateKey(): Key = when(this) {
    is RsaJsonWebKey -> this.rsaPrivateKey
    is EllipticCurveJsonWebKey -> this.ecPrivateKey
    is PublicJsonWebKey -> this.privateKey
    is OctetSequenceJsonWebKey -> this.key
    else -> this.key
}

/**
 * Resolves the public key of the json web key for signature verification and encryption.
 * If [this] is a symmetric key (octet-sequence), returns the key directly.
 */
fun JsonWebKey.resolvePublicKey(): Key = when(this) {
    is RsaJsonWebKey -> this.getRsaPublicKey()
    is EllipticCurveJsonWebKey -> this.ecPublicKey
    is PublicJsonWebKey -> this.publicKey
    is OctetSequenceJsonWebKey -> this.key
    else -> this.key
}

fun JsonWebKeySet.mustKeyForJweKeyManagement(keyAlg: JweKeyManagementAlgorithm): JsonWebKey =
    this.findJsonWebKey(null, null, Use.ENCRYPTION, keyAlg.algorithmIdentifier)
        ?: throw ServerError.internal("Cannot find key for managing ${keyAlg.spec}.")

fun JsonWebKeySet.mustKeyForSignature(signAlg: JwtSigningAlgorithm): JsonWebKey =
        this.findJsonWebKey(null, null, Use.SIGNATURE, signAlg.algorithmIdentifier)
        ?: throw ServerError.internal("Cannot find key for signing ${signAlg.spec}.")

fun JsonWebKeySet.mustKeyWithId(keyId: String): JsonWebKey =
        this.findJsonWebKey(keyId, null, null, null)
            ?: throw ServerError.internal("Cannot find key with id $keyId.")