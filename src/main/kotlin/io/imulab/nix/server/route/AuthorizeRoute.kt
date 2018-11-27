package io.imulab.nix.server.route

import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.space
import io.imulab.nix.oidc.OidcRequestForm
import io.imulab.nix.oidc.RequestStrategy
import io.imulab.nix.oidc.StandardScope
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
    private val requestStrategy: RequestStrategy,
    private val clientLookup: ClientLookup
) {

    fun accept(ctx: PipelineContext<Unit, ApplicationCall>) = runBlocking {
        val requestForm = OidcRequestForm(httpForm = ctx.context.autoParameters().toMutableMap())

        // next: produce OidcAuthorizeRequest

        // check if it contains openid scope

        // if so, try requestStrategy and merge into a new unified request.

        // next up: preliminary validation (should understand what is re-entry and skip if it's an re-entry)

        // authentication

        // consent

        // post validation (everything should be nice and sound)

        // handlers

        // render response

        println(requestForm.clientId)
    }
}