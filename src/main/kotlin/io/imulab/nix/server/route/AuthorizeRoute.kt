package io.imulab.nix.server.route

import io.ktor.application.call
import io.ktor.response.respondText
import io.ktor.routing.Routing
import io.ktor.routing.get
import org.kodein.di.Kodein

fun Routing.authorize(di: Kodein) {
    get("/oauth/authorize") {
        call.respondText("hello world")
    }
}