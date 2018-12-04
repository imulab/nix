package io.imulab.nix.oidc.reserved

import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jws.AlgorithmIdentifiers

/**
 * Signature algorithm used to sign and verify signatures.
 */
enum class JwtSigningAlgorithm(
    val spec: String,
    val algorithmIdentifier: String
) {
    HS256("HS256", AlgorithmIdentifiers.HMAC_SHA256),
    HS384("HS384", AlgorithmIdentifiers.HMAC_SHA384),
    HS512("HS512", AlgorithmIdentifiers.HMAC_SHA512),
    RS256("RS256", AlgorithmIdentifiers.RSA_USING_SHA256),
    RS384("RS384", AlgorithmIdentifiers.RSA_USING_SHA384),
    RS512("RS512", AlgorithmIdentifiers.RSA_USING_SHA512),
    ES256("ES256", AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256),
    ES384("ES384", AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384),
    ES512("ES512", AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512),
    PS256("PS256", AlgorithmIdentifiers.RSA_PSS_USING_SHA256),
    PS384("PS384", AlgorithmIdentifiers.RSA_PSS_USING_SHA384),
    PS512("PS512", AlgorithmIdentifiers.RSA_PSS_USING_SHA512),
    None("none", AlgorithmIdentifiers.NONE);

    fun whitelisted(): AlgorithmConstraints = AlgorithmConstraints(
        AlgorithmConstraints.ConstraintType.WHITELIST,
        algorithmIdentifier
    )
}