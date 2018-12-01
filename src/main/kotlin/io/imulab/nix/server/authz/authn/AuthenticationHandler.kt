package io.imulab.nix.server.authz.authn

import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm

interface AuthenticationHandler {

    suspend fun attemptAuthenticate(
        form: OidcRequestForm,
        request: OidcAuthorizeRequest,
        rawCall: Any)
}