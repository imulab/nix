package io.imulab.nix.crypt.alg

import io.imulab.nix.support.OAuthEnum
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers

enum class EncryptionAlgorithm(
    override val specValue: String,
    private val fullName: String,
    val alg: String): OAuthEnum {

    A128CBC_HS256(
        specValue = "A128CBC-HS256",
        fullName = "AES_128_CBC_HMAC_SHA_256",
        alg = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256
    ),
    A192CBC_HS384(
        specValue = "A192CBC-HS384",
        fullName = "AES_192_CBC_HMAC_SHA_384",
        alg = ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384
    ),
    A256CBC_HS512(
        specValue = "A256CBC-HS512",
        fullName = "AES_256_CBC_HMAC_SHA_512",
        alg = ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512),
    A128GCM(
        specValue = "A128GCM",
        fullName = "AES GCM using 128-bit key",
        alg = ContentEncryptionAlgorithmIdentifiers.AES_128_GCM),
    A192GCM(
        specValue = "A192GCM",
        fullName = "AES GCM using 192-bit key",
        alg = ContentEncryptionAlgorithmIdentifiers.AES_192_GCM),
    A256GCM(
        specValue = "A256GCM",
        fullName = "AES GCM using 256-bit key",
        alg = ContentEncryptionAlgorithmIdentifiers.AES_256_GCM)
}