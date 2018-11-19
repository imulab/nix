package io.imulab.nix

import io.imulab.nix.config.appModule
import io.imulab.nix.config.memoryPersistenceModule
import io.imulab.nix.route.AuthorizeRoute
import io.imulab.nix.route.TokenRoute
import io.ktor.application.Application
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import org.kodein.di.Kodein
import org.kodein.di.conf.global

fun Application.nix() {
    with(Kodein.global) {
        mutable = true
        addImport(memoryPersistenceModule())
        addImport(appModule())
    }

    routing {
        get("/oauth/authorize") { AuthorizeRoute.accept(this) }
        post("/oauth/token") { TokenRoute.accept(this) }
    }
}

fun main(args: Array<String>) {
    embeddedServer(Netty,
        watchPaths = listOf("nix"),
        port = 8080,
        module = Application::nix
    ).start(wait = true)
}