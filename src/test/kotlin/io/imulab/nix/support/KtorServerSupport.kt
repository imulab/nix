package io.imulab.nix.support

import io.ktor.routing.Routing
import io.ktor.routing.routing
import io.ktor.server.testing.TestApplicationRequest
import io.ktor.server.testing.TestApplicationResponse
import io.ktor.server.testing.withTestApplication

object KtorServerSupport {

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