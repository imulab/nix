package io.imulab.nix.server.authz.authn

import io.imulab.nix.oidc.OidcAuthorizeRequest
import io.imulab.nix.oidc.OidcRequestForm

interface AuthenticationHandler {

    suspend fun attemptAuthenticate(form: OidcRequestForm, request: OidcAuthorizeRequest)
}