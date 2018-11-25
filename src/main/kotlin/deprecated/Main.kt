package deprecated

import deprecated.config.appModule
import deprecated.config.memoryPersistenceModule
import deprecated.route.AuthorizeRoute
import deprecated.route.TokenRoute
import io.ktor.application.Application
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import org.kodein.di.Kodein
import org.kodein.di.conf.global
import org.kodein.di.erased.instance

fun Application.nix() {
    with(Kodein.global) {
        mutable = true
        addImport(memoryPersistenceModule())
        addImport(appModule())
    }

    val authorizeRoute: AuthorizeRoute by Kodein.global.instance()
    val tokenRoute: TokenRoute by Kodein.global.instance()

    routing {
        get("/oauth/authorize") { authorizeRoute.accept(this) }
        post("/oauth/token") { tokenRoute.accept(this) }
    }
}

fun main(args: Array<String>) {
    embeddedServer(Netty,
        watchPaths = listOf("nix"),
        port = 8080,
        module = Application::nix
    ).start(wait = true)
}