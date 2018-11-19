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
import org.kodein.di.conf.KodeinGlobalAware
import org.kodein.di.erased.instance

class TokenRoute: KodeinGlobalAware {

    private val provider: OAuthProvider by kodein.instance()

    fun accept(ctx: PipelineContext<Unit, ApplicationCall>) = runBlocking {
        val httpRequest = HttpRequest(ctx.call)
        val httpResponse = HttpResponse(ctx.call, this)

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
}