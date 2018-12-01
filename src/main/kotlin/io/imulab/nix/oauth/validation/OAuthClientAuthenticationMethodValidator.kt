package io.imulab.nix.oauth.validation

import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.reserved.AuthenticationMethod

/**
 * Validates client authentication method is one of `{client_secret_basic, client_secret_post}`.
 */
object OAuthClientAuthenticationMethodValidator : SpecDefinitionValidator {
    override fun validate(value: String): String {
        return when (value) {
            AuthenticationMethod.clientSecretBasic,
            AuthenticationMethod.clientSecretPost -> value
            else -> throw ServerError.internal("Illegal client authentication method named <$value>.")
        }
    }
}