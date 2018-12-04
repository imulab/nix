package io.imulab.nix.oidc.handler

import io.imulab.nix.oauth.error.InvalidScope
import io.imulab.nix.oauth.exactly
import io.imulab.nix.oauth.handler.AccessRequestHandler
import io.imulab.nix.oauth.handler.AuthorizeRequestHandler
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.ResponseType
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oauth.token.strategy.AuthorizeCodeStrategy
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oidc.handler.helper.TokenHashHelper
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.oidc.request.OidcSessionRepository
import io.imulab.nix.oidc.reserved.IdTokenClaim
import io.imulab.nix.oidc.reserved.StandardScope
import io.imulab.nix.oidc.response.OidcTokenEndpointResponse
import io.imulab.nix.oidc.token.IdTokenStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OidcAuthorizeCodeHandler(
    private val idTokenStrategy: IdTokenStrategy,
    private val oidcSessionRepository: OidcSessionRepository
) : AuthorizeRequestHandler, AccessRequestHandler {

    override suspend fun handleAuthorizeRequest(request: OAuthAuthorizeRequest, response: AuthorizeEndpointResponse) {
        if (!request.responseTypes.exactly(ResponseType.code) || request.session !is OidcSession)
            return

        check(response.code.isNotEmpty()) {
            "Upstream handler should have issued authorization code. Was handler misplaced?"
        }

        withContext(Dispatchers.IO) {
            launch {
                oidcSessionRepository.createOidcSession(response.code, request.session)
            }
        }
    }

    override suspend fun updateSession(request: OAuthAccessRequest) {}

    override suspend fun handleAccessRequest(request: OAuthAccessRequest, response: TokenEndpointResponse) {
        if (!request.grantTypes.exactly(GrantType.authorizationCode) || request.session !is OidcSession)
            return

        check(response is OidcTokenEndpointResponse) {
            "Called should have supplied an OidcTokenEndpointResponse."
        }

        check(request.client is OidcClient) {
            "Called should have supplied an OidcClient"
        }

        check(response.accessToken.isNotEmpty()) {
            "Upstream handler should have issued access token. Was handler misplaced?"
        }

        val authorizeSession = oidcSessionRepository.getOidcSession(request.code)
        if (!authorizeSession.grantedScopes.contains(StandardScope.openid))
            throw InvalidScope.notGranted(StandardScope.openid)

        request.session.idTokenClaims[IdTokenClaim.accessTokenHash] =
                TokenHashHelper.leftMostHash(response.accessToken, request.client.idTokenSignedResponseAlgorithm)
        response.idToken = idTokenStrategy.generateToken(request)
    }
}