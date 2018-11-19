package io.imulab.nix.route

import io.imulab.astrea.domain.request.AuthorizeRequest
import io.imulab.astrea.domain.response.AuthorizeResponse
import io.imulab.astrea.provider.OAuthProvider
import io.imulab.nix.astrea.HttpRequest
import io.imulab.nix.astrea.HttpResponse
import io.imulab.nix.consent.ConsentStrategy
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.runBlocking
import org.kodein.di.conf.KodeinGlobalAware
import org.kodein.di.erased.instance

class AuthorizeRoute: KodeinGlobalAware {

    private val provider: OAuthProvider by kodein.instance()
    private val consentStrategy: ConsentStrategy by kodein.instance()

    fun accept(ctx: PipelineContext<Unit, ApplicationCall>) = runBlocking {
        val httpRequest = HttpRequest(ctx.call)
        val httpResponse = HttpResponse(ctx.call, this)

        var authorizeRequest: AuthorizeRequest? = null
        val authorizeResponse: AuthorizeResponse?

        try {
            authorizeRequest = provider.newAuthorizeRequest(httpRequest)

            consentStrategy.acquireConsent(httpRequest, authorizeRequest)

            authorizeResponse = provider.newAuthorizeResponse(authorizeRequest, authorizeRequest.getSession()!!)

            provider.encodeAuthorizeResponse(httpResponse, authorizeRequest, authorizeResponse)
        } catch (e: Exception) {
            provider.encodeAuthorizeError(httpResponse, authorizeRequest, e)
        } finally {
            httpResponse.flush()
        }
    }
}