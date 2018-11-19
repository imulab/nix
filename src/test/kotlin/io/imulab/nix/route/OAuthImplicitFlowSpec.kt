package io.imulab.nix.route

import com.google.gson.Gson
import io.imulab.astrea.domain.*
import io.imulab.nix.support.KtorServerSupport
import io.imulab.nix.support.forEachAutoClear
import io.ktor.http.*
import io.ktor.routing.Routing
import io.ktor.server.testing.TestApplicationResponse
import org.assertj.core.api.Assertions.assertThat
import org.kodein.di.Kodein
import org.kodein.di.conf.global
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthImplicitFlowSpec : Spek({

    afterEachTest {
        Kodein.global.clear()
    }

    describe("OAuth Implicit Flow") {
        it("acquire access token directly from authorize endpoint") {
            ImplicitFlow.authorizeEndpointLeg(responseAssertion = {
                assertThat(status()).isEqualTo(HttpStatusCode.Found)
                Url(headers["Location"]!!).fragment.decodeURLQueryComponent()
                    .split("&")
                    .map { it.split("=").let { p -> Pair(p[0], p[1]) } }
                    .toMap()
                    .let { assertThat(it) }
                    .run {
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_TOKEN_TYPE] }.asString().isEqualTo(TokenType.Bearer.specValue)
                        extracting { it[PARAM_STATE] }.asString().isEqualTo("12345678")
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar")
                        extracting { it[PARAM_EXPIRES_IN] }.asString().satisfies { it.toLong() > 0 }
                    }
            })
        }
    }

    describe("OAuth Implicit Flow Failure Modes") {
        it("unregistered scope") {
            ImplicitFlow.authorizeEndpointLeg(
                paramModifier = {
                    it.removeIf { p -> p.first == PARAM_SCOPE }
                    it.add(PARAM_SCOPE to "foo unregistered")
                },
                responseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.Unauthorized)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it["error"] }.asString().isEqualTo("invalid_scope")
                    }
                }
            )
        }

        it("missing required parameter") {
            listOf(
                PARAM_CLIENT_ID,
                PARAM_SCOPE,
                PARAM_REDIRECT_URI,
                PARAM_RESPONSE_TYPE,
                PARAM_STATE
            ).forEachAutoClear { missing ->
                ImplicitFlow.authorizeEndpointLeg(
                    paramModifier = {
                        it.removeIf { p -> p.first == missing }
                    },
                    responseAssertion = {
                        assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                        with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                            extracting { it["error"] }.asString().isEqualTo("invalid_request")
                        }
                    }
                )
            }
        }

        it("unregistered redirect_uri") {
            ImplicitFlow.authorizeEndpointLeg(
                paramModifier = {
                    it.removeIf { p -> p.first == PARAM_REDIRECT_URI }
                    it.add(PARAM_REDIRECT_URI to "http://localhost:8888/unregistered")
                },
                responseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it["error"] }.asString().isEqualTo("invalid_request")
                    }
                }
            )
        }

        it("insufficient state entropy") {
            ImplicitFlow.authorizeEndpointLeg(
                paramModifier = {
                    it.removeIf { p -> p.first == PARAM_STATE }
                    it.add(PARAM_STATE to "0")
                },
                responseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it["error"] }.asString().isEqualTo("invalid_request")
                    }
                }
            )
        }
    }

}) {
    private object ImplicitFlow {

        fun authorizeEndpointLeg(
            serverSetup: Routing.() -> Unit = KtorServerSupport.testServerSetup,
            paramModifier: (MutableList<Pair<String, String>>) -> Unit = {},
            responseAssertion: TestApplicationResponse.() -> Unit
        ) {
            KtorServerSupport.flow(
                serverSetup = serverSetup,
                requestsAndResponses = listOf(
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "foo",
                                PARAM_SCOPE to "foo bar",
                                PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                                PARAM_RESPONSE_TYPE to ResponseType.Token.specValue,
                                PARAM_STATE to "12345678"
                            ).also(paramModifier)
                            method = HttpMethod.Get
                            uri = "/oauth/authorize" + (if (params.isEmpty()) "" else "?${params.formUrlEncode()}")

                        },
                        responseAssertion = responseAssertion
                    )
                )
            )
        }
    }
}