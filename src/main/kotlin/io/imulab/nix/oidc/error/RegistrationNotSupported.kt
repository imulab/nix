package io.imulab.nix.oidc.error

import io.imulab.nix.oauth.error.OAuthException

// registration_not_supported
// --------------------------
// The OP does not support use of the registration parameter defined in Section
// 7.2.1 (https://openid.net/specs/openid-connect-core-1_0.html#RegistrationParameter).
object RegistrationNotSupported {
    private const val code = "registration_not_supported"
    private const val status = 400

    val unsupported: () -> Throwable =
        {
            OAuthException(
                status,
                code,
                "The use of registration parameter is not supported."
            )
        }
}