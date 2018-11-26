package io.imulab.nix.oidc

import io.imulab.nix.oauth.OAuthClientAuthenticationMethodValidator
import io.imulab.nix.oauth.OAuthException
import io.imulab.nix.oauth.ReservedWordValidator
import io.imulab.nix.oauth.ServerError

object OidcClientAuthenticationMethodValidator : ReservedWordValidator {
    override fun validate(value: String): String {
        return try {
            OAuthClientAuthenticationMethodValidator.validate(value)
        } catch (e: OAuthException) {
            if (e.error == ServerError.code) {
                when (value) {
                    AuthenticationMethod.clientSecretJwt,
                    AuthenticationMethod.privateKeyJwt,
                    AuthenticationMethod.none -> value
                    else -> throw ServerError.internal("Illegal client authentication method named <$value>.")
                }
            } else {
                throw e
            }
        }
    }
}