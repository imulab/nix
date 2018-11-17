package io.imulab.nix.route

import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.response.respond
import io.ktor.util.pipeline.PipelineContext
import kotlinx.coroutines.runBlocking

fun PipelineContext<Unit, ApplicationCall>.tokenRoute() {
    runBlocking {
        call.respond("OK from token endpoint")
    }
}