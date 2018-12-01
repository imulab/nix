package io.imulab.nix.oidc.reserved

/**
 * Authentication method applicable to client. This is an extension to
 * the values existing in [io.imulab.nix.oauth.AuthenticationMethod] and
 * represents the authentication method that wasn't mentioned in OAuth 2.0
 * specification but mentioned in Open ID Connect 1.0 specification.
 */
object AuthenticationMethod {
    const val clientSecretJwt = "client_secret_jwt"
    const val privateKeyJwt = "private_key_jwt"
    const val none = "none"
}