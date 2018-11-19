package io.imulab.nix.support

import io.imulab.nix.config.appModule
import io.imulab.nix.config.memoryPersistenceModule
import io.imulab.nix.route.AuthorizeRoute
import io.imulab.nix.route.TokenRoute
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.testing.TestApplicationRequest
import io.ktor.server.testing.TestApplicationResponse
import io.ktor.server.testing.withTestApplication
import org.kodein.di.Kodein
import org.kodein.di.conf.global

object KtorServerSupport {

    val testServerSetup: Routing.() -> Unit = {
        Kodein.global.mutable = true
        Kodein.global.addImport(application.memoryPersistenceModule())
        Kodein.global.addImport(application.appModule())

        get("/oauth/authorize") { AuthorizeRoute.accept(this) }
        post("/oauth/token") { TokenRoute.accept(this) }
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

    fun flow(serverSetup: Routing.() -> Unit,
             requestsAndResponses: List<RequestAndResponse> = emptyList()) = withTestApplication(
        moduleFunction = {
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