package io.imulab.nix.oidc.reserved

import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers

/**
 * Content encoding algorithm used for JWE encryption/decryption.
 * [None] is a special value to indicate this algorithm is not
 * specified. Fields adopting [None] should be treated as if the
 * value is null.
 */
enum class JweContentEncodingAlgorithm(val spec: String, val algorithmIdentifier: String) {
    A128CBC_HS256("A128CBC-HS256", ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256),
    A192CBC_HS384("A192CBC-HS384", ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384),
    A256CBC_HS512("A256CBC-HS512", ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512),
    A128GCM("A128GCM", ContentEncryptionAlgorithmIdentifiers.AES_128_GCM),
    A192GCM("A192GCM", ContentEncryptionAlgorithmIdentifiers.AES_192_GCM),
    A256GCM("A256GCM", ContentEncryptionAlgorithmIdentifiers.AES_256_GCM),
    None("none", "");

    fun whitelisted(): AlgorithmConstraints = AlgorithmConstraints(
        AlgorithmConstraints.ConstraintType.WHITELIST,
        algorithmIdentifier
    )
}