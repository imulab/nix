package io.imulab.nix.oauth.handler

import io.imulab.nix.oauth.OAuthContext
import io.imulab.nix.oauth.error.InvalidGrant
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.exactly
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.reserved.ResponseType
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oauth.token.storage.AccessTokenRepository
import io.imulab.nix.oauth.token.storage.AuthorizeCodeRepository
import io.imulab.nix.oauth.token.storage.RefreshTokenRepository
import io.imulab.nix.oauth.token.strategy.AccessTokenStrategy
import io.imulab.nix.oauth.token.strategy.AuthorizeCodeStrategy
import io.imulab.nix.oauth.token.strategy.RefreshTokenStrategy
import io.imulab.nix.oauth.reserved.StandardScope

class OAuthAuthorizeCodeHandler(
    private val oauthContext: OAuthContext,
    private val authorizeCodeStrategy: AuthorizeCodeStrategy,
    private val authorizeCodeRepository: AuthorizeCodeRepository,
    private val accessTokenStrategy: AccessTokenStrategy,
    private val accessTokenRepository: AccessTokenRepository,
    private val refreshTokenStrategy: RefreshTokenStrategy,
    private val refreshTokenRepository: RefreshTokenRepository
) : AuthorizeRequestHandler, AccessRequestHandler {

    override suspend fun handleAuthorizeRequest(request: OAuthAuthorizeRequest, response: AuthorizeEndpointResponse) {
        if (!request.responseTypes.exactly(ResponseType.code))
            return

        val code = authorizeCodeStrategy.generateCode(request)

        authorizeCodeRepository.createAuthorizeCodeSession(code, request)

        response.let {
            it.code = code
            if (request.state.isNotEmpty())
                it.state = request.state
            it.scope = request.session.grantedScopes
        }

        response.handledResponseTypes.add(ResponseType.code)
    }

    override suspend fun updateSession(request: OAuthAccessRequest) {
        if (!request.grantTypes.exactly(GrantType.authorizationCode))
            return

        val authorizeRequest = authorizeCodeRepository.getAuthorizeCodeSession(request.code).also { restored ->
            if (restored !is OAuthAuthorizeRequest)
                throw ServerError.internal("restored request is not oauth authorize request.")
            authorizeCodeStrategy.verifyCode(request.code, restored)
        } as OAuthAuthorizeRequest

        if (request.client.id != authorizeRequest.client.id)
            throw InvalidGrant.impersonate()
        else if (request.redirectUri != authorizeRequest.redirectUri)
            throw InvalidRequest.unmet("redirect_uri must match authorize request.")

        request.session.merge(authorizeRequest.session)
    }

    override suspend fun handleAccessRequest(request: OAuthAccessRequest, response: TokenEndpointResponse) {
        if (!request.grantTypes.exactly(GrantType.authorizationCode))
            return

        accessTokenStrategy.generateToken(request).let { accessToken ->
            accessTokenRepository.createAccessTokenSession(accessToken, request)
            response.accessToken = accessToken
            response.tokenType = "bearer"
            response.expiresIn = oauthContext.accessTokenLifespan.toSeconds()
        }

        if (request.session.grantedScopes.contains(StandardScope.offlineAccess)) {
            refreshTokenStrategy.generateToken(request).let { refreshToken ->
                refreshTokenRepository.createRefreshTokenSession(refreshToken, request)
                response.refreshToken = refreshToken
            }
        }

        response.scope = request.session.grantedScopes.toSet()
    }
}