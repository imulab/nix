package io.imulab.nix.route

import com.google.gson.Gson
import io.imulab.astrea.domain.*
import io.imulab.nix.support.KtorServerSupport
import io.ktor.http.*
import io.ktor.routing.Routing
import io.ktor.server.testing.TestApplicationResponse
import io.ktor.server.testing.setBody
import org.assertj.core.api.Assertions.assertThat
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthAuthorizeCodeFlowSpec : Spek({

    describe("OAuth Authorize Code Flow") {
        it("Obtain an authorize code and use it to acquire access token") {
            AuthorizeCodeFlow.tokenEndpointLeg(
                authorizeEndpointResponseAssertion = {
                    assertThat(headers.contains(HttpHeaders.Location)).isTrue()
                    assertThat(Url(headers["Location"]!!).parameters[PARAM_CODE]).asString().isNotEmpty()
                },
                tokenEndpointResponseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_TOKEN_TYPE] }.asString().isEqualTo(TokenType.Bearer.specValue)
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar")
                        satisfies {
                            assertThat(it[PARAM_EXPIRES_IN] as Double).isGreaterThan(0.0)
                        }
                    }
                }
            )
        }

        it("scope rewrite is ignored") {
            AuthorizeCodeFlow.tokenEndpointLeg(
                tokenEndpointParamModifier = {
                    it.add(PARAM_SCOPE to "foo foobar")
                },
                tokenEndpointResponseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar")
                        extracting { it[PARAM_SCOPE] }.asString().doesNotContain("foobar")
                    }
                }
            )
        }
    }

    describe("OAuth Authorize Code Flow Authorize Endpoint Failure Modes") {

        describe("invalid_request") {

            it("required parameter is missing") {
                listOf(PARAM_CLIENT_ID, PARAM_SCOPE, PARAM_RESPONSE_TYPE, PARAM_STATE).forEach { missing ->
                    AuthorizeCodeFlow.authorizeEndpointLeg(
                        paramModifier = { it.removeIf { p -> p.first == missing } }
                    ) {
                        assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                        with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                            extracting { it["status_code"] }.asString()
                                .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                            extracting { it["error"] }.asString()
                                .isEqualTo("invalid_request")
                            extracting { it["error_description"] }.asString()
                                .contains("missing")
                        }
                    }
                }
            }

            it("invalid response type") {
                AuthorizeCodeFlow.authorizeEndpointLeg(
                    paramModifier = {
                        it.removeIf { p -> p.first == PARAM_RESPONSE_TYPE }
                        it.add(PARAM_RESPONSE_TYPE to "invalid")
                    }
                ) {
                    assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it["status_code"] }.asString()
                            .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                        extracting { it["error"] }.asString()
                            .isEqualTo("invalid_request")
                    }
                }
            }

            it("invalid or unregistered redirect uri") {
                listOf(
                    "http://localhost:8888/wrong",
                    "http://insecure.com/callback"
                ).forEach { redirectUri ->
                    AuthorizeCodeFlow.authorizeEndpointLeg(
                        paramModifier = {
                            it.removeIf { p -> p.first == PARAM_REDIRECT_URI }
                            it.add(PARAM_REDIRECT_URI to redirectUri)
                        }
                    ) {
                        assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                        with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                            extracting { it["status_code"] }.asString()
                                .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                            extracting { it["error"] }.asString()
                                .isEqualTo("invalid_request")
                        }
                    }
                }
            }

            it("insufficient state entropy") {
                AuthorizeCodeFlow.authorizeEndpointLeg(
                    paramModifier = {
                        it.removeIf { p -> p.first == PARAM_STATE }
                        it.add(PARAM_STATE to "0")
                    }
                ) {
                    assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it["status_code"] }.asString()
                            .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                        extracting { it["error"] }.asString()
                            .isEqualTo("invalid_request")
                        println(content)
                    }
                }
            }
        }

    }

    describe("OAuth Authorize Code Flow Token Endpoint Failure Modes") {

        describe("invalid_request") {
            it("not a form") {
                AuthorizeCodeFlow.tokenEndpointLeg(
                    tokenEndpointHeaders = emptyMap(),
                    tokenEndpointResponseAssertion = {
                        assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                        with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                            extracting { it["status_code"] }.asString()
                                .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                            extracting { it["error"] }.asString()
                                .isEqualTo("invalid_request")
                        }
                    }
                )
            }

            it("missing a required parameter") {
                listOf(
                    PARAM_REDIRECT_URI,
                    PARAM_GRANT_TYPE
                ).forEach { missing ->
                    AuthorizeCodeFlow.tokenEndpointLeg(
                        tokenEndpointParamModifier = {
                            it.removeIf { p -> p.first == missing }
                        },
                        tokenEndpointResponseAssertion = {
                            assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                            with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                                extracting { it["status_code"] }.asString()
                                    .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                                extracting { it["error"] }.asString()
                                    .isEqualTo("invalid_request")
                            }
                        }
                    )
                }

            }
        }

        describe("invalid_grant") {
            it("missing authorization code grant") {
                AuthorizeCodeFlow.tokenEndpointLeg(
                    tokenEndpointParamModifier = {
                        it.removeIf { p -> p.first == PARAM_CODE }
                    },
                    tokenEndpointResponseAssertion = {
                        assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                        with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                            extracting { it["status_code"] }.asString()
                                .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                            extracting { it["error"] }.asString()
                                .isEqualTo("invalid_grant")
                        }
                    }
                )
            }

            it("authorization code is invalid") {
                AuthorizeCodeFlow.tokenEndpointLeg(
                    tokenEndpointParamModifier = {
                        it.removeIf { p -> p.first == PARAM_CODE }
                        it.add(PARAM_CODE to "a-totally-invalid-code.a-totally-invalid-signature")
                    },
                    tokenEndpointResponseAssertion = {
                        assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                        with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                            extracting { it["status_code"] }.asString()
                                .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                            extracting { it["error"] }.asString()
                                .isEqualTo("invalid_grant")
                        }
                    }
                )
            }

            it("mismatched redirect_uri") {
                AuthorizeCodeFlow.tokenEndpointLeg(
                    tokenEndpointParamModifier = {
                        it.removeIf { p -> p.first == PARAM_REDIRECT_URI }
                        it.add(PARAM_REDIRECT_URI to "http://localhost:8888/callback2")
                    },
                    tokenEndpointResponseAssertion = {
                        assertThat(status()).isEqualTo(HttpStatusCode.BadRequest)
                        with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                            extracting { it["status_code"] }.asString()
                                .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                            extracting { it["error"] }.asString()
                                .isEqualTo("invalid_grant")
                        }
                    }
                )
            }
        }

        describe("invalid_client") {
            it("missing client_id or client_secret") {
                listOf(PARAM_CLIENT_ID, PARAM_CLIENT_SECRET).forEach { missing ->
                    AuthorizeCodeFlow.tokenEndpointLeg(
                        tokenEndpointParamModifier = {
                            it.removeIf { p -> p.first == missing }
                        },
                        tokenEndpointResponseAssertion = {
                            assertThat(status()).isEqualTo(HttpStatusCode.Unauthorized)
                            with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                                extracting { it["status_code"] }.asString()
                                    .isEqualTo(HttpStatusCode.Unauthorized.value.toString())
                                extracting { it["error"] }.asString()
                                    .isEqualTo("invalid_client")
                            }
                        }
                    )
                }
            }

            it("client not registered") {
                AuthorizeCodeFlow.tokenEndpointLeg(
                    tokenEndpointParamModifier = {
                        it.removeIf { p -> p.first == PARAM_CLIENT_ID }
                        it.add(PARAM_CLIENT_ID to "not-registered-client")
                    },
                    tokenEndpointResponseAssertion = {
                        assertThat(status()).isEqualTo(HttpStatusCode.Unauthorized)
                        with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                            extracting { it["status_code"] }.asString()
                                .isEqualTo(HttpStatusCode.Unauthorized.value.toString())
                            extracting { it["error"] }.asString()
                                .isEqualTo("invalid_client")
                        }
                    }
                )
            }
        }
    }
}) {
    private object AuthorizeCodeFlow {

        fun authorizeEndpointLeg(
            serverSetup: Routing.() -> Unit = KtorServerSupport.testServerSetup,
            paramModifier: (MutableList<Pair<String, String>>) -> Unit,
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
                                PARAM_RESPONSE_TYPE to "code",
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

        fun tokenEndpointLeg(
            serverSetup: Routing.() -> Unit = KtorServerSupport.testServerSetup,
            authorizeEndpointParamModifier: (MutableList<Pair<String, String>>) -> Unit = {},
            tokenEndpointParamModifier: (MutableList<Pair<String, String>>) -> Unit = {},
            tokenEndpointHeaders: Map<String, String> = mapOf(
                HttpHeaders.ContentType to ContentType.Application.FormUrlEncoded.toString()
            ),
            authorizeEndpointResponseAssertion: TestApplicationResponse.() -> Unit = {},
            tokenEndpointResponseAssertion: TestApplicationResponse.() -> Unit = {}
        ) {
            var authorizeCode: String? = null

            KtorServerSupport.flow(
                serverSetup = serverSetup,
                requestsAndResponses = listOf(
                    // make authorize code request
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "foo",
                                PARAM_SCOPE to "foo bar",
                                PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                                PARAM_RESPONSE_TYPE to "code",
                                PARAM_STATE to "12345678"
                            ).also(authorizeEndpointParamModifier)
                            method = HttpMethod.Get
                            uri = "/oauth/authorize" + (if (params.isEmpty()) "" else "?${params.formUrlEncode()}")
                        },
                        responseAssertion = {
                            this.apply(authorizeEndpointResponseAssertion)
                            authorizeCode = Url(headers["Location"]!!).parameters[PARAM_CODE]
                        }
                    ),
                    // make access request
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            checkNotNull(authorizeCode)
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "foo",
                                PARAM_CLIENT_SECRET to "s3cret",
                                PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                                PARAM_GRANT_TYPE to GrantType.AuthorizationCode.specValue,
                                PARAM_CODE to authorizeCode!!
                            ).also(tokenEndpointParamModifier)

                            method = HttpMethod.Post
                            uri = "/oauth/token"
                            tokenEndpointHeaders.forEach { t, u -> addHeader(t, u) }
                            if (params.isNotEmpty())
                                setBody(params.formUrlEncode())
                        },
                        responseAssertion = tokenEndpointResponseAssertion
                    )
                )
            )
        }

    }
}