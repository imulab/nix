package io.imulab.nix.support

import io.imulab.nix.config.appModule
import io.imulab.nix.config.memoryPersistenceModule
import io.imulab.nix.route.AuthorizeRoute
import io.imulab.nix.route.TokenRoute
import io.ktor.config.MapApplicationConfig
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.testing.TestApplicationRequest
import io.ktor.server.testing.TestApplicationResponse
import io.ktor.server.testing.withTestApplication
import io.ktor.util.KtorExperimentalAPI
import org.kodein.di.Kodein
import org.kodein.di.conf.global
import org.kodein.di.erased.instance

object KtorServerSupport {

    val testServerSetup: Routing.() -> Unit = {
        Kodein.global.mutable = true
        Kodein.global.addImport(application.memoryPersistenceModule())
        Kodein.global.addImport(application.appModule(), allowOverride = true)

        val authorizeRoute: AuthorizeRoute by Kodein.global.instance()
        val tokenRoute: TokenRoute by Kodein.global.instance()

        get("/oauth/authorize") { authorizeRoute.accept(this) }
        post("/oauth/token") { tokenRoute.accept(this) }
    }

    fun oneShot(clientSetup: TestApplicationRequest.() -> Unit,
                serverSetup: Routing.() -> Unit,
                responseAssertion: TestApplicationResponse.() -> Unit = {}) = withTestApplication(
        moduleFunction = {
            routing { this.apply(serverSetup) }
        }, test = {
            with(handleRequest(clientSetup)) {
                response.apply(responseAssertion)
            }
            Unit
        })

    @UseExperimental(KtorExperimentalAPI::class)
    fun flow(serverSetup: Routing.() -> Unit,
             extraConfig: Map<String, List<String>> = emptyMap(),
             requestsAndResponses: List<RequestAndResponse> = emptyList()) = withTestApplication(
        moduleFunction = {
            (environment.config as MapApplicationConfig).apply {
                extraConfig.forEach { t, u ->
                    when (u.size) {
                        0 -> return@forEach
                        1 -> put(t, u[0])
                        else -> put(t, u)
                    }
                }
            }
            routing { this.apply(serverSetup) }
        }, test = {
            requestsAndResponses.forEach { reqAndResp ->
                with(handleRequest(reqAndResp.request)) {
                    response.apply(reqAndResp.responseAssertion)
                }
            }
            Unit
        })

    class RequestAndResponse(val request: TestApplicationRequest.() -> Unit,
                             val responseAssertion: TestApplicationResponse.() -> Unit = {})
}