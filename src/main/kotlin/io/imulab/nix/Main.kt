package io.imulab.nix

import io.imulab.nix.oauth.provider
import io.imulab.nix.route.authorizeRoute
import io.imulab.nix.route.tokenRoute
import io.ktor.application.Application
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty

fun Application.nix() {

    routing {
        get("/oauth/authorize") { authorizeRoute(provider()) }
        post("/oauth/token") { tokenRoute() }
    }
}

fun main(args: Array<String>) {
    embeddedServer(Netty,
        watchPaths = listOf("nix"),
        port = 8080,
        module = Application::nix
    ).start(wait = true)
}