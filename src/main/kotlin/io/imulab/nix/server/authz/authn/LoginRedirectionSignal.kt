package io.imulab.nix.server.authz.authn

import io.imulab.nix.oauth.OAuthResponse
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oidc.LoginTokenParam

/**
 * Special exception to signal an HTTP redirection to the login endpoint.
 */
class LoginRedirectionSignal(
    private val loginEndpoint: String,
    private val loginToken: String,
    private val authorizeRequestId: String,
    private val callbackUri: String,
    private val nonce: String
) : RuntimeException(), OAuthResponse {
    override val status: Int
        get() = 302
    override val headers: Map<String, String>
        get() = mapOf("Location" to loginEndpoint)
    override val data: Map<String, String>
        get() = mapOf(
            Param.Internal.loginToken to loginToken,
            LoginTokenParam.authorizeRequestId to authorizeRequestId,
            LoginTokenParam.nonce to nonce,
            LoginTokenParam.redirectUri to callbackUri
        )
}