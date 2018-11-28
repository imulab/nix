package io.imulab.nix.server.route

import io.imulab.nix.oauth.OAuthRequestValidation
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oidc.*
import io.imulab.nix.oauth.assertType
import io.imulab.nix.server.autoParameters
import io.imulab.nix.server.toMutableMap
import io.ktor.application.ApplicationCall
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.runBlocking
import org.kodein.di.Kodein
import org.kodein.di.erased.instance

fun Routing.authorize(di: Kodein) {
    get("/oauth/authorize") {
        val provider by di.instance<AuthorizeRouteProvider>()
        provider.accept(this)
    }
}

class AuthorizeRouteProvider(
    private val requestProducer: OidcAuthorizeRequestProducer,
    private val preValidation: OAuthRequestValidation,
    private val postValidation: OAuthRequestValidation
) {

    fun accept(ctx: PipelineContext<Unit, ApplicationCall>) = runBlocking {
        val requestForm = OidcRequestForm(httpForm = ctx.context.autoParameters().toMutableMap())

        val authorizeRequest = requestProducer.produce(requestForm).assertType<OidcAuthorizeRequest>()

        // next up: preliminary validation (should understand what is re-entry and skip if it's an re-entry)
        // TODO re-entry identification is pending
        preValidation.validate(authorizeRequest)

        // authentication

        // consent

        // post validation (everything should be nice and sound)
        postValidation.validate(authorizeRequest)

        // handlers

        // render response

        println(requestForm.clientId)
    }
}