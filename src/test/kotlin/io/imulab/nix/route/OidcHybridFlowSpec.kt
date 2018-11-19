package io.imulab.nix.route

import com.google.gson.Gson
import io.imulab.astrea.domain.*
import io.imulab.nix.consent.ConsentStrategy
import io.imulab.nix.consent.OidcConsentStrategy
import io.imulab.nix.support.KtorServerSupport
import io.imulab.nix.support.decodedFragmentsAsMap
import io.ktor.http.*
import io.ktor.routing.Routing
import io.ktor.server.testing.TestApplicationResponse
import io.ktor.server.testing.setBody
import org.assertj.core.api.Assertions.assertThat
import org.kodein.di.Kodein
import org.kodein.di.conf.global
import org.kodein.di.erased.bind
import org.kodein.di.erased.singleton
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OidcHybridFlowSpec: Spek({

    afterEachTest {
        Kodein.global.clear()
    }

    describe("Open ID Connect Hybrid Flow") {
        it("scope = code id_token") {
            OidcHybridFlow.tokenEndpointLeg(
                authorizeEndpointResponseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.Found)
                    with(assertThat(Url(headers["Location"]!!).decodedFragmentsAsMap())) {
                        extracting { it[PARAM_CODE] }.asString().isNotEmpty()
                        extracting { it[PARAM_STATE] }.asString().isEqualTo("12345678")
                        extracting { it[PARAM_ID_TOKEN] }.asString().isNotEmpty()
                    }
                },
                tokenEndpointResponseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar", SCOPE_OPENID)
                        extracting { it[PARAM_ID_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                    }
                }
            )
        }

        it("scope = code token") {
            OidcHybridFlow.tokenEndpointLeg(
                authorizeEndpointParamModifier = {
                    it.removeIf { p -> p.first == PARAM_RESPONSE_TYPE }
                    it.add(PARAM_RESPONSE_TYPE to "${ResponseType.Code.specValue} ${ResponseType.Token.specValue}")
                },
                authorizeEndpointResponseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.Found)
                    with(assertThat(Url(headers["Location"]!!).decodedFragmentsAsMap())) {
                        extracting { it[PARAM_CODE] }.asString().isNotEmpty()
                        extracting { it[PARAM_STATE] }.asString().isEqualTo("12345678")
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                    }
                },
                tokenEndpointResponseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar", SCOPE_OPENID)
                        extracting { it[PARAM_ID_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                    }
                }
            )
        }

        it("scope = code token id_token") {
            OidcHybridFlow.tokenEndpointLeg(
                authorizeEndpointParamModifier = {
                    it.removeIf { p -> p.first == PARAM_RESPONSE_TYPE }
                    it.add(PARAM_RESPONSE_TYPE to "${ResponseType.Code.specValue} ${ResponseType.Token.specValue} ${ResponseType.IdToken.specValue}")
                },
                authorizeEndpointResponseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.Found)
                    with(assertThat(Url(headers["Location"]!!).decodedFragmentsAsMap())) {
                        extracting { it[PARAM_CODE] }.asString().isNotEmpty()
                        extracting { it[PARAM_STATE] }.asString().isEqualTo("12345678")
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_ID_TOKEN] }.asString().isNotEmpty()
                    }
                },
                tokenEndpointResponseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    with(assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar", SCOPE_OPENID)
                        extracting { it[PARAM_ID_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                    }
                }
            )
        }
    }
}) {

    private object OidcHybridFlow {

        fun tokenEndpointLeg(
            serverSetup: Routing.() -> Unit = {
                this.apply(KtorServerSupport.testServerSetup)
                Kodein.global.addConfig {
                    bind<ConsentStrategy>(overrides = true) with singleton { OidcConsentStrategy }
                }
            },
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
                extraConfig = mapOf(
                    "flow.oidc.authorize" to listOf("true"),
                    "flow.oidc.implicit" to listOf("true"),
                    "flow.oidc.hybrid" to listOf("true")
                ),
                requestsAndResponses = listOf(
                    // make authorize code request
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "bar",
                                PARAM_SCOPE to "foo bar $SCOPE_OPENID",
                                PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                                PARAM_RESPONSE_TYPE to "${ResponseType.Code.specValue} ${ResponseType.IdToken.specValue}",
                                PARAM_STATE to "12345678",
                                PARAM_NONCE to "87654321",
                                PARAM_PROMPT to Prompt.Login.specValue,
                                PARAM_MAX_AGE to "600"
                            ).also(authorizeEndpointParamModifier)
                            method = HttpMethod.Get
                            uri = "/oauth/authorize" + (if (params.isEmpty()) "" else "?${params.formUrlEncode()}")
                        },
                        responseAssertion = {
                            this.apply(authorizeEndpointResponseAssertion)
                            authorizeCode = Url(headers["Location"]!!).decodedFragmentsAsMap()[PARAM_CODE]
                        }
                    ),
                    // make access request
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            checkNotNull(authorizeCode)
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "bar",
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