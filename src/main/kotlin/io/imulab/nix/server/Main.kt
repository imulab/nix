package io.imulab.nix.server

import io.imulab.nix.server.authz.authn.session.AuthenticationSession
import io.imulab.nix.server.config.DependencyInjection
import io.imulab.nix.server.config.ServerContext
import io.imulab.nix.server.route.authorize
import io.imulab.nix.server.route.token
import io.ktor.application.Application
import io.ktor.application.install
import io.ktor.config.ApplicationConfig
import io.ktor.config.HoconApplicationConfig
import io.ktor.routing.routing
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
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

    val kodein = Kodein {
        val di = DependencyInjection(environment.config)

        importOnce(di.configuration, allowOverride = true)
        importOnce(di.routeProviders, allowOverride = true)

        onReady {
            val config: ServerContext = instance()
            config.validate()
        }
    }

    routing {
        authorize(kodein)
        token(kodein)
    }
}

fun main(args: Array<String>) {
    val env = applicationEngineEnvironment {
        module { nix() }
        connector {
            port = 8080
        }
    }

    embeddedServer(Netty, env).start(wait = true)
}