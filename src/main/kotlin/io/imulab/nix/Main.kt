package io.imulab.nix

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.CallLogging
import io.ktor.features.DefaultHeaders
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty

fun Application.nix() {
    routing {
        get("/") {
            // TODO object takes a call object
            call.respondText(text = "Hello World", contentType = ContentType.Text.Plain)
        }
    }
}

fun main(args: Array<String>) {
    embeddedServer(Netty, watchPaths = listOf("nix"), port = 8080, module = Application::nix)
        .start(wait = true)
}