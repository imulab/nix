package io.imulab.nix.server

import io.imulab.nix.server.route.authorize
import io.imulab.nix.server.route.token
import io.ktor.application.Application
import io.ktor.config.ApplicationConfig
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.util.KtorExperimentalAPI
import org.kodein.di.Kodein
import org.kodein.di.erased.bind
import org.kodein.di.erased.instance
import org.kodein.di.erased.singleton

@UseExperimental(KtorExperimentalAPI::class)
fun Application.nix() {

    val di = Kodein {
        bind<ApplicationConfig>() with singleton { environment.config }

        import(DependencyInjection.configuration)
        import(DependencyInjection.routeProviders)

        onReady {
            val config: ServerContext = instance()
            config.validate()
        }
    }

    routing {
        authorize(di)
        token(di)
    }
}

fun main(args: Array<String>) {
    embeddedServer(
        Netty,
        watchPaths = listOf("nix"),
        port = 8080,
        module = Application::nix
    ).start(wait = true)
}