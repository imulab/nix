package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.reserved.SubjectType

/**
 * Validates subject type values. The universe is `{public, pairwise}`.
 */
object SubjectTypeValidator : SpecDefinitionValidator {
    override fun validate(value: String): String {
        return when(value) {
            SubjectType.public, SubjectType.pairwise -> value
            else -> throw IllegalArgumentException("$value is not a valid subject type.")
        }
    }
}