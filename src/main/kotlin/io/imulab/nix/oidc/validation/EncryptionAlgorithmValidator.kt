package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.reserved.JweKeyManagementAlgorithm

/**
 * Validates the JWE encryption algorithm. The universe is everything specified in [JweKeyManagementAlgorithm].
 */
object EncryptionAlgorithmValidator: SpecDefinitionValidator {
    override fun validate(value: String): String {
        if (!JweKeyManagementAlgorithm.values().map { it.spec }.contains(value))
            throw IllegalArgumentException("$value is not a valid key management encryption algorithm.")
        return value
    }
}