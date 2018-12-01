package io.imulab.nix.oauth.validation

import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.reserved.ClientType

/**
 * Validates `client_type = {public, confidential}`.
 */
object ClientTypeValidator : SpecDefinitionValidator {
    override fun validate(value: String): String {
        return when (value) {
            ClientType.public, ClientType.confidential -> value
            else -> throw ServerError.internal("Illegal client type <$value>.")
        }
    }
}