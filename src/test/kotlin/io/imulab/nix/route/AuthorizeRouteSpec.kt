package io.imulab.nix.route

import io.imulab.astrea.domain.*
import io.imulab.nix.consent.AutoConsentStrategy
import io.imulab.nix.oauth.provider
import io.imulab.nix.support.KtorServerSupport
import io.ktor.application.application
import io.ktor.http.HttpMethod
import io.ktor.http.formUrlEncode
import io.ktor.routing.get
import io.ktor.routing.post
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object AuthorizeRouteSpec: Spek({

    describe("correct request") {
        it("""
            should return authorize code
        """.trimIndent()) {
            KtorServerSupport.test(
                clientSetup = {
                    method = HttpMethod.Get
                    uri = "/oauth/authorize?" + listOf(
                        PARAM_CLIENT_ID to "foo",
                        PARAM_SCOPE to "foo bar",
                        PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                        PARAM_RESPONSE_TYPE to "code",
                        PARAM_STATE to "12345678"
                    ).formUrlEncode()
                },
                serverSetup = {
                    get("/oauth/authorize") { authorizeRoute(this.application.provider(), AutoConsentStrategy) }
                },
                responseAssertion = {
                    println(this.headers["Location"])
                }
            )
        }
    }
})