package io.imulab.nix.route

import io.imulab.astrea.domain.request.AccessRequest
import io.imulab.astrea.domain.response.AccessResponse
import io.imulab.astrea.domain.session.impl.DefaultJwtSession
import io.imulab.astrea.provider.OAuthProvider
import io.imulab.nix.astrea.HttpRequest
import io.imulab.nix.astrea.HttpResponse
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.runBlocking

fun PipelineContext<Unit, ApplicationCall>.tokenRoute(provider: OAuthProvider) = runBlocking {
    val httpRequest = HttpRequest(call)
    val httpResponse = HttpResponse(call, this)

    var accessRequest: AccessRequest? = null
    val accessResponse: AccessResponse

    try {
        accessRequest = provider.newAccessRequest(httpRequest, DefaultJwtSession.Builder().also {
            it.getClaims().setGeneratedJwtId()
        }.build())

        accessResponse = provider.newAccessResponse(accessRequest)

        provider.encodeAccessResponse(httpResponse, accessRequest, accessResponse)
    } catch (e: Exception) {
        provider.encodeAccessError(httpResponse, accessRequest, e)
        //e.printStackTrace()
    } finally {
        httpResponse.flush()
    }
}