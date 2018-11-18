package io.imulab.nix.support

import io.imulab.nix.consent.AutoConsentStrategy
import io.imulab.nix.oauth.provider
import io.imulab.nix.route.authorizeRoute
import io.imulab.nix.route.tokenRoute
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.server.testing.TestApplicationRequest
import io.ktor.server.testing.TestApplicationResponse
import io.ktor.server.testing.withTestApplication

object KtorServerSupport {

    val testServerSetup: Routing.() -> Unit = {
        val provider = application.provider()
        get("/oauth/authorize") { authorizeRoute(provider, AutoConsentStrategy) }
        post("/oauth/token") { tokenRoute(provider) }
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