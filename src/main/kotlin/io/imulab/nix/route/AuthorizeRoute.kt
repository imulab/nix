package io.imulab.nix.route

import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.provider.OAuthProvider
import io.imulab.nix.astrea.HttpRequest
import io.imulab.nix.astrea.HttpResponse
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.runBlocking

fun PipelineContext<Unit, ApplicationCall>.authorizeRoute(provider: OAuthProvider) = runBlocking {
    val httpRequest = HttpRequest(call)
    val httpResponse = HttpResponse(call, this)
    var authorizeRequest: AuthorizeRequest? = null

    try {
        authorizeRequest = provider.newAuthorizeRequest(httpRequest)
        val authorizeResponse = provider.newAuthorizeResponse(
            authorizeRequest,
            DefaultJwtSession.Builder().also {
                it.getClaims().setGeneratedJwtId()
            }.build())
        provider.encodeAuthorizeResponse(httpResponse, authorizeRequest, authorizeResponse)
    } catch (e: Exception) {
        provider.encodeAuthorizeError(httpResponse, authorizeRequest, e)
    } finally {
        httpResponse.flush()
    }
}