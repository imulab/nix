package io.imulab.nix.oauth.provider

import io.imulab.nix.oauth.request.AuthorizeRequest
import io.imulab.nix.oauth.response.AuthorizeResponse
import io.imulab.nix.oauth.session.OAuthSession
import io.ktor.application.ApplicationCall

interface AuthorizeEndpointProvider {

    suspend fun newAuthorizeRequest(call: ApplicationCall): AuthorizeRequest

    suspend fun newAuthorizeResponse(request: AuthorizeRequest, session: OAuthSession): AuthorizeResponse

    suspend fun writeAuthorizeResponse(call: ApplicationCall, request: AuthorizeRequest, response: AuthorizeResponse)

    suspend fun writeAuthorizeError(call: ApplicationCall, request: AuthorizeRequest?, error: Throwable)
}