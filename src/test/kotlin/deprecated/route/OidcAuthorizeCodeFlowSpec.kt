package deprecated.route

import com.google.gson.Gson
import io.imulab.astrea.domain.*
import deprecated.consent.ConsentStrategy
import deprecated.consent.OidcConsentStrategy
import deprecated.support.KtorServerSupport
import io.ktor.http.*
import io.ktor.routing.Routing
import io.ktor.server.testing.TestApplicationResponse
import io.ktor.server.testing.setBody
import org.assertj.core.api.Assertions
import org.kodein.di.Kodein
import org.kodein.di.conf.global
import org.kodein.di.erased.bind
import org.kodein.di.erased.singleton
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OidcAuthorizeCodeFlowSpec: Spek({

    afterEachTest {
        Kodein.global.clear()
    }

    describe("Open ID Connect Authorize Code Flow") {
        it("Obtain an authorize code and use it to acquire access token and id token") {
            OidcAuthorizeCodeFlow.tokenEndpointLeg(
                authorizeEndpointResponseAssertion = {
                    Assertions.assertThat(headers.contains(HttpHeaders.Location)).isTrue()
                    Assertions.assertThat(Url(headers["Location"]!!).parameters[PARAM_CODE]).asString().isNotEmpty()
                },
                tokenEndpointResponseAssertion = {
                    Assertions.assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    with(Assertions.assertThat(Gson().fromJson(content, HashMap::class.java))) {
                        extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_ID_TOKEN] }.asString().isNotEmpty()
                        extracting { it[PARAM_TOKEN_TYPE] }.asString().isEqualTo(TokenType.Bearer.specValue)
                        extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar", SCOPE_OPENID)
                        satisfies {
                            Assertions.assertThat(it[PARAM_EXPIRES_IN] as Double).isGreaterThan(0.0)
                        }
                    }
                }
            )
        }
    }

    describe("Open ID Connect Authorize Code Flow Failure Modes") {
        it("max_age exceeded") {
            OidcAuthorizeCodeFlow.authorizeEndpointLeg(
                paramModifier = {
                    /*
                    ATTENTION:
                    ----------
                    This test may break if max_age is limited to non-negative values in the future.

                    A negative max_age is not a realistic setting. But because auth_time and rat setting
                    in the development strategies is set to now-10 and now-20 respectively, a negative max_age
                    allows the test to force an error situation where auth_time + max_age < rat when prompt=Login.
                     */
                    it.removeIf { p -> p.first == PARAM_MAX_AGE }
                    it.add(PARAM_MAX_AGE to "-600")
                },
                responseAssertion = {
                    with(Assertions.assertThat(Url(headers["Location"]!!).parameters)) {
                        extracting { it["status_code"] }.asString()
                            .isEqualTo(HttpStatusCode.BadRequest.value.toString())
                        extracting { it["error"] }.asString()
                            .isEqualTo("invalid_request")
                    }
                }
            )
        }
    }
}) {
    private object OidcAuthorizeCodeFlow {

        fun authorizeEndpointLeg(
            serverSetup: Routing.() -> Unit = {
                this.apply(KtorServerSupport.testServerSetup)
                Kodein.global.addConfig {
                    bind<ConsentStrategy>(overrides = true) with singleton { OidcConsentStrategy }
                }
            },
            paramModifier: (MutableList<Pair<String, String>>) -> Unit = {},
            responseAssertion: TestApplicationResponse.() -> Unit = {}
        ) {
            KtorServerSupport.flow(
                serverSetup = serverSetup,
                extraConfig = mapOf(
                    "flow.oidc.authorize" to listOf("true")
                ),
                requestsAndResponses = listOf(
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "bar",
                                PARAM_SCOPE to "foo bar $SCOPE_OPENID",
                                PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                                PARAM_RESPONSE_TYPE to "code",
                                PARAM_STATE to "12345678",
                                PARAM_PROMPT to Prompt.Login.specValue,
                                PARAM_MAX_AGE to "600"
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
                    "flow.oidc.authorize" to listOf("true")
                ),
                requestsAndResponses = listOf(
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "bar",
                                PARAM_SCOPE to "foo bar $SCOPE_OPENID",
                                PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                                PARAM_RESPONSE_TYPE to ResponseType.Code.specValue,
                                PARAM_STATE to "12345678",
                                PARAM_PROMPT to Prompt.Login.specValue,
                                PARAM_MAX_AGE to "600"
                            ).also(authorizeEndpointParamModifier)
                            method = HttpMethod.Get
                            uri = "/oauth/authorize" + (if (params.isEmpty()) "" else "?${params.formUrlEncode()}")

                        },
                        responseAssertion = {
                            this.apply(authorizeEndpointResponseAssertion)
                            authorizeCode = Url(headers["Location"]!!).parameters[PARAM_CODE]
                        }
                    ),
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