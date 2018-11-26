package io.imulab.nix.server.route

import io.ktor.application.call
import io.ktor.response.respondText
import io.ktor.routing.Routing
import io.ktor.routing.post
import org.kodein.di.Kodein

fun Routing.token(di: Kodein) {
    post("/oauth/token") {
        call.respondText("hello world again")
    }
}