package io.imulab.nix.oidc.handler

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.handler.AccessRequestHandler
import io.imulab.nix.oauth.handler.AuthorizeRequestHandler
import io.imulab.nix.oauth.handler.helper.AccessTokenHelper
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.reserved.ResponseType.code
import io.imulab.nix.oauth.reserved.ResponseType.token
import io.imulab.nix.oidc.reserved.ResponseType.idToken
import io.imulab.nix.oauth.response.AuthorizeEndpointResponse
import io.imulab.nix.oauth.token.storage.AuthorizeCodeRepository
import io.imulab.nix.oauth.token.strategy.AuthorizeCodeStrategy
import io.imulab.nix.oidc.client.OidcClient
import io.imulab.nix.oidc.handler.helper.TokenHashHelper
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.oidc.request.OidcSessionRepository
import io.imulab.nix.oidc.reserved.IdTokenClaim
import io.imulab.nix.oidc.reserved.StandardScope
import io.imulab.nix.oidc.response.OidcAuthorizeEndpointResponse
import io.imulab.nix.oidc.token.IdTokenStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class OidcHybridHandler(
    private val oidcAuthorizeCodeHandler: OidcAuthorizeCodeHandler,
    private val authorizeCodeStrategy: AuthorizeCodeStrategy,
    private val authorizeCodeRepository: AuthorizeCodeRepository,
    private val idTokenStrategy: IdTokenStrategy,
    private val accessTokenHelper: AccessTokenHelper,
    private val oidcSessionRepository: OidcSessionRepository
) : AuthorizeRequestHandler, AccessRequestHandler by oidcAuthorizeCodeHandler {

    override suspend fun handleAuthorizeRequest(request: OAuthAuthorizeRequest, response: AuthorizeEndpointResponse) {
        if (!request.shouldBeHandled())
            return

        if (request.state.isNotEmpty())
            response.state = request.state

        val authorizeCodeJob = if (request.responseTypes.contains(code)) {
            withContext(Dispatchers.IO) {
                launch {
                    authorizeCodeStrategy.generateCode(request).also { authorizeCode ->
                        authorizeCodeRepository.createAuthorizeCodeSession(authorizeCode, request)
                        response.code = authorizeCode
                        val session = request.session.assertType<OidcSession>()
                        session.idTokenClaims[IdTokenClaim.codeHash] =
                                TokenHashHelper.leftMostHash(
                                    authorizeCode,
                                    request.client.assertType<OidcClient>().idTokenSignedResponseAlgorithm
                                )
                        if (session.grantedScopes.contains(StandardScope.openid))
                            oidcSessionRepository.createOidcSession(authorizeCode, session)
                    }
                    response.handledResponseTypes.add(code)
                }
            }
        } else null

        val accessTokenJob = if (request.responseTypes.contains(token)) {
            withContext(Dispatchers.IO) {
                launch {
                    accessTokenHelper.createAccessToken(request, response).join()
                    request.session.assertType<OidcSession>().idTokenClaims[IdTokenClaim.accessTokenHash] =
                            TokenHashHelper.leftMostHash(
                                response.accessToken,
                                request.client.assertType<OidcClient>().idTokenSignedResponseAlgorithm
                            )
                    response.handledResponseTypes.add(token)
                }
            }
        } else null

        authorizeCodeJob?.join()
        accessTokenJob?.join()

        if (request.responseTypes.contains(idToken) && request.session.grantedScopes.contains(StandardScope.openid))
            response.assertType<OidcAuthorizeEndpointResponse>().idToken = idTokenStrategy.generateToken(request)
        response.handledResponseTypes.add(idToken)
    }

    private fun OAuthAuthorizeRequest.shouldBeHandled(): Boolean {
        return when (responseTypes.size) {
            2 -> responseTypes.containsAll(listOf(code, token)) ||
                    responseTypes.containsAll(listOf(code, idToken))
            3 -> responseTypes.containsAll(listOf(code, token, idToken))
            else -> false
        }
    }
}