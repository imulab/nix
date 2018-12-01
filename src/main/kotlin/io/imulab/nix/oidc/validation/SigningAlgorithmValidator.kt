package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm

/**
 * Validates the JWT signing algorithm. The universe is everything specified in [JwtSigningAlgorithm].
 */
object SigningAlgorithmValidator: SpecDefinitionValidator {
    override fun validate(value: String): String {
        if (!JwtSigningAlgorithm.values().map { it.spec }.contains(value))
            throw IllegalArgumentException("$value is not a valid signing algorithm.")
        return value
    }
}