package io.imulab.nix.oidc.response

import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oidc.reserved.OidcParam

class OidcTokenEndpointResponse(
    override var idToken: String = ""
) : TokenEndpointResponse(), IdTokenResponse {

    override val data: Map<String, String>
        get() {
            val m = super.data as MutableMap
            m[OidcParam.idToken] = idToken
            return m
        }
}