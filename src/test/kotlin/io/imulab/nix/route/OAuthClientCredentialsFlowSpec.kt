package io.imulab.nix.route

import com.google.gson.Gson
import io.imulab.astrea.domain.*
import io.imulab.nix.support.KtorServerSupport
import io.ktor.http.*
import io.ktor.routing.Routing
import io.ktor.server.testing.TestApplicationResponse
import io.ktor.server.testing.setBody
import org.assertj.core.api.Assertions
import org.kodein.di.Kodein
import org.kodein.di.conf.global
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthClientCredentialsFlowSpec: Spek({

    afterEachTest {
        Kodein.global.clear()
    }

    describe("OAuth Client Credentials Flow") {
        it("acquire access token from token endpoint") {
            ClientCredentialsFlow.tokenEndpointLeg(
                responseAssertion = {
                    Assertions.assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    with(Assertions.assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar")
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_TOKEN_TYPE] }.asString().isEqualTo(TokenType.Bearer.specValue)
                        extracting { it[PARAM_EXPIRES_IN] }.satisfies { it.toString().toDouble() > 0 }
                    }
                }
            )
        }

        it("acquire access token and refresh token from token endpoint") {
            ClientCredentialsFlow.tokenEndpointLeg(
                paramModifier = {
                    it.removeIf { p -> p.first == PARAM_SCOPE }
                    it.add(PARAM_SCOPE to "foo bar $SCOPE_OFFLINE")
                },
                responseAssertion = {
                    Assertions.assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    with(Assertions.assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar", SCOPE_OFFLINE)
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_REFRESH_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_TOKEN_TYPE] }.asString().isEqualTo(TokenType.Bearer.specValue)
                        extracting { it[PARAM_EXPIRES_IN] }.satisfies { it.toString().toDouble() > 0 }
                    }
                }
            )
        }
    }

    describe("OAuth Client Credentials Flow Failure Modes") {
        it("authentication failure") {
            ClientCredentialsFlow.tokenEndpointLeg(
                paramModifier = {
                    it.removeIf { p -> p.first == PARAM_CLIENT_SECRET }
                    it.add(PARAM_CLIENT_SECRET to "invalid")
                },
                responseAssertion = {
                    Assertions.assertThat(status()).isEqualTo(HttpStatusCode.Unauthorized)
                }
            )
        }
    }
}) {
    private object ClientCredentialsFlow {

        fun tokenEndpointLeg(
            serverSetup: Routing.() -> Unit = KtorServerSupport.testServerSetup,
            paramModifier: (MutableList<Pair<String, String>>) -> Unit = {},
            headers: Map<String, String> = mapOf(
                HttpHeaders.ContentType to ContentType.Application.FormUrlEncoded.toString()
            ),
            responseAssertion: TestApplicationResponse.() -> Unit
        ) {
            KtorServerSupport.flow(
                serverSetup = serverSetup,
                requestsAndResponses = listOf(
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "foo",
                                PARAM_CLIENT_SECRET to "s3cret",
                                PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                                PARAM_GRANT_TYPE to GrantType.ClientCredentials.specValue,
                                PARAM_SCOPE to "foo bar"
                            ).also(paramModifier)

                            method = HttpMethod.Post
                            uri = "/oauth/token"
                            headers.forEach { t, u -> addHeader(t, u) }
                            if (params.isNotEmpty())
                                setBody(params.formUrlEncode())
                        },
                        responseAssertion = responseAssertion
                    )
                )
            )
        }
    }
}