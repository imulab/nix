package io.imulab.nix.oidc.reserved

import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers

/**
 * Key management algorithm used for JWE encryption/decryption.
 * [None] is a special value to indicate this algorithm is not
 * specified. Fields adopting [None] should be treated as if
 * the value is null.
 */
enum class JweKeyManagementAlgorithm(
    val spec: String,
    val algorithmIdentifier: String,
    val isSymmetric: Boolean
) {

    RSA1_5("RSA1_5", KeyManagementAlgorithmIdentifiers.RSA1_5, false),
    RSA_OAEP("RSA-OAEP", KeyManagementAlgorithmIdentifiers.RSA_OAEP, false),
    RSA_OAEP_256("RSA-OAEP-256", KeyManagementAlgorithmIdentifiers.RSA_OAEP_256, false),
    ECDH_ES("ECDH-ES", KeyManagementAlgorithmIdentifiers.ECDH_ES, false),
    ECDH_ES_A128KW("ECDH-ES+A128KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW, false),
    ECDH_ES_A192KW("ECDH-ES+A192KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW, false),
    ECDH_ES_A256KW("ECDH-ES+A256KW", KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW, false),
    A128KW("A128KW", KeyManagementAlgorithmIdentifiers.A128KW, true),
    A192KW("A192KW", KeyManagementAlgorithmIdentifiers.A192KW, true),
    A256KW("A256KW", KeyManagementAlgorithmIdentifiers.A256KW, true),
    A128GCMKW("A128GCMKW", KeyManagementAlgorithmIdentifiers.A128GCMKW, true),
    A192GCMKW("A192GCMKW", KeyManagementAlgorithmIdentifiers.A192GCMKW, true),
    A256GCMKW("A256GCMKW", KeyManagementAlgorithmIdentifiers.A256GCMKW, true),
    PBES2_HS256_A128KW("PBES2-HS256+A128KW", KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW, true),
    PBES2_HS384_A192KW("PBES2-HS384+A192KW", KeyManagementAlgorithmIdentifiers.PBES2_HS384_A192KW, true),
    PBES2_HS512_A256KW("PBES2-HS512+A256KW", KeyManagementAlgorithmIdentifiers.PBES2_HS512_A256KW, true),
    DIRECT("dir", KeyManagementAlgorithmIdentifiers.DIRECT, false),
    None("none", "", false);

    fun whitelisted(): AlgorithmConstraints = AlgorithmConstraints(
        AlgorithmConstraints.ConstraintType.WHITELIST,
        algorithmIdentifier
    )
}