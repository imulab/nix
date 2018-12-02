package io.imulab.nix.server.route

import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oauth.assertType
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcAuthorizeRequestProducer
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.server.authz.authn.AuthenticationProvider
import io.imulab.nix.server.authz.authn.LoginRedirectionSignal
import io.imulab.nix.server.authz.consent.ConsentProvider
import io.imulab.nix.server.authz.consent.ConsentRedirectionSignal
import io.imulab.nix.server.autoParameters
import io.imulab.nix.server.toMutableMap
import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.runBlocking
import org.kodein.di.Kodein
import org.kodein.di.erased.instance
import java.lang.Exception

fun Routing.authorize(di: Kodein) {
    get("/oauth/authorize") {
        val provider: AuthorizeRouteProvider by di.instance()
        provider.accept(this)
    }
}

class AuthorizeRouteProvider(
    private val requestProducer: OidcAuthorizeRequestProducer,
    private val preValidation: OAuthRequestValidation,
    private val authenticationProvider: AuthenticationProvider,
    private val consentProvider: ConsentProvider,
    private val postValidation: OAuthRequestValidation
) {

    fun accept(ctx: PipelineContext<Unit, ApplicationCall>) = runBlocking {
        try {
            doAccept(ctx)
        } catch (e: Exception) {
            when (e) {
                is LoginRedirectionSignal -> {

                }
                is ConsentRedirectionSignal -> {

                }
                is OAuthException -> {

                }
                else -> {

                }
            }
        }
    }

    private suspend fun doAccept(ctx: PipelineContext<Unit, ApplicationCall>) {
        val requestForm =
            OidcRequestForm(httpForm = ctx.context.autoParameters().toMutableMap())

        val authorizeRequest = requestProducer.produce(requestForm).assertType<OidcAuthorizeRequest>()

        // next up: preliminary validation, skip validation related to session.
        preValidation.validate(authorizeRequest)

        // authentication
        authenticationProvider.tryAuthenticate(requestForm, authorizeRequest, ctx.call)

        // consent
        consentProvider.tryAuthorize(requestForm, authorizeRequest, ctx.call)

        // post validation (everything should be nice and sound)
        postValidation.validate(authorizeRequest)

        // handlers

        // render response

        println(requestForm.clientId)
    }
}