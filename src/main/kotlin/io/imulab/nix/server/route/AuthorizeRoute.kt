package io.imulab.nix.server.route

import io.imulab.nix.oidc.OidcRequestForm
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

class AuthorizeRouteProvider() {

    fun accept(ctx: PipelineContext<Unit, ApplicationCall>) = runBlocking {
        val requestForm = OidcRequestForm(httpForm = ctx.context.autoParameters().toMutableMap())

        println(requestForm.clientId)
    }
}