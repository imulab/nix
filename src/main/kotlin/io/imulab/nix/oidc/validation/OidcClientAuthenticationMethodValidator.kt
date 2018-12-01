package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.validation.OAuthClientAuthenticationMethodValidator
import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.reserved.AuthenticationMethod

/**
 * An extension to [OAuthClientAuthenticationMethodValidator]. In OIDC spec, we have a few additional methods. Now,
 * the universe is `{client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt, none}`.
 */
object OidcClientAuthenticationMethodValidator : SpecDefinitionValidator {
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