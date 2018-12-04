package io.imulab.nix.oauth.handler

import io.imulab.nix.oauth.exactly
import io.imulab.nix.oauth.handler.helper.AccessTokenHelper
import io.imulab.nix.oauth.handler.helper.RefreshTokenHelper
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.reserved.GrantType
import io.imulab.nix.oauth.response.TokenEndpointResponse
import io.imulab.nix.oauth.token.storage.AccessTokenRepository
import io.imulab.nix.oauth.token.storage.RefreshTokenRepository
import io.imulab.nix.oauth.token.strategy.RefreshTokenStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OAuthRefreshHandler(
    private val accessTokenHelper: AccessTokenHelper,
    private val refreshTokenHelper: RefreshTokenHelper,
    private val accessTokenRepository: AccessTokenRepository,
    private val refreshTokenStrategy: RefreshTokenStrategy,
    private val refreshTokenRepository: RefreshTokenRepository
) : AccessRequestHandler {

    override suspend fun updateSession(request: OAuthAccessRequest) {
        if (!request.grantTypes.exactly(GrantType.refreshToken))
            return

        val originalRequest = request.refreshToken
            .also { refreshTokenStrategy.verifyToken(it, request) }
            .let { refreshTokenRepository.getRefreshTokenSession(it) }

        request.session.merge(originalRequest.session)
        request.session.originalRequestId = originalRequest.id
    }

    override suspend fun handleAccessRequest(request: OAuthAccessRequest, response: TokenEndpointResponse) {
        if (!request.grantTypes.exactly(GrantType.refreshToken))
            return

        val refreshTokenRemoval = withContext(Dispatchers.IO) {
            launch {
                refreshTokenRepository.deleteRefreshTokenAssociatedWithRequest(request.session.originalRequestId)
            }
        }
        val accessTokenRemoval = withContext(Dispatchers.IO) {
            launch {
                accessTokenRepository.deleteAccessTokenAssociatedWithRequest(request.session.originalRequestId)
            }
        }

        val accessTokenCreation = accessTokenHelper.createAccessToken(request, response)
        val refreshTokenCreation = refreshTokenHelper.createRefreshToken(request, response)

        response.scope = request.session.grantedScopes.toSet()

        refreshTokenRemoval.join()
        accessTokenRemoval.join()
        accessTokenCreation.join()
        refreshTokenCreation.join()
    }
}