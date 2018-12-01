package io.imulab.nix.server

import io.imulab.nix.server.authz.authn.session.AuthenticationSession
import io.imulab.nix.server.route.authorize
import io.imulab.nix.server.route.token
import io.ktor.application.Application
import io.ktor.application.install
import io.ktor.config.ApplicationConfig
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.sessions.SessionStorageMemory
import io.ktor.sessions.Sessions
import io.ktor.sessions.cookie
import io.ktor.util.KtorExperimentalAPI
import org.kodein.di.Kodein
import org.kodein.di.erased.bind
import org.kodein.di.erased.instance
import org.kodein.di.erased.singleton

@UseExperimental(KtorExperimentalAPI::class)
fun Application.nix() {

    install(Sessions) {
        cookie<AuthenticationSession>(
            name = "auth",
            storage = SessionStorageMemory()
        ) {
            cookie.path = "/"
            // TODO add encryption in the future so we can just store in user browser.
        }
    }

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