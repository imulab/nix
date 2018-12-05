package io.imulab.nix.oauth.handler

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.exactly
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.ResponseType
import io.imulab.nix.oauth.reserved.StandardScope
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse
import io.imulab.nix.oauth.token.storage.AccessTokenRepository
import io.imulab.nix.oauth.token.strategy.AccessTokenStrategy

class OAuthImplicitHandler(
    private val oauthContext: OAuthContext,
    private val accessTokenStrategy: AccessTokenStrategy,
    private val accessTokenRepository: AccessTokenRepository
) : AuthorizeRequestHandler {

    override suspend fun handleAuthorizeRequest(request: OAuthAuthorizeRequest, response: AuthorizeEndpointResponse) {
        if (!request.responseTypes.exactly(ResponseType.token))
            return

        request.client.mustGrantType(GrantType.implicit)

        response.scope = request.session.grantedScopes.apply { remove(StandardScope.offlineAccess) }
        response.state = request.state

        accessTokenStrategy.generateToken(request).also { accessToken ->
            accessTokenRepository.createAccessTokenSession(accessToken, request)
            response.accessToken = accessToken
            response.tokenType = "bearer"
            response.expiresIn = oauthContext.accessTokenLifespan.toSeconds()
        }

        response.handledResponseTypes.add(ResponseType.token)
    }
}