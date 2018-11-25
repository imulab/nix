package deprecated.route

import io.imulab.astrea.domain.*
import deprecated.consent.ConsentStrategy
import deprecated.consent.OidcConsentStrategy
import deprecated.support.KtorServerSupport
import io.ktor.http.*
import io.ktor.routing.Routing
import io.ktor.server.testing.TestApplicationResponse
import org.assertj.core.api.Assertions
import org.kodein.di.Kodein
import org.kodein.di.conf.global
import org.kodein.di.erased.bind
import org.kodein.di.erased.singleton
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OidcImplicitFlowSpec: Spek({

    afterEachTest {
        Kodein.global.clear()
    }

    describe("Open ID Connect Implicit Flow") {
        it("acquire access token and id token from authorize endpoint") {
            OidcImplicitFlow.authorizeEndpointLeg(
                responseAssertion = {
                    Assertions.assertThat(status()).isEqualTo(HttpStatusCode.Found)
                    Url(headers["Location"]!!).fragment.decodeURLQueryComponent()
                        .split("&")
                        .map { it.split("=").let { p -> Pair(p[0], p[1]) } }
                        .toMap()
                        .let { Assertions.assertThat(it) }
                        .run {
                            extracting { it[PARAM_ACCESS_TOKEN] }.asString().isNotEmpty()
                            extracting { it[PARAM_ID_TOKEN] }.asString().isNotEmpty()
                            extracting { it[PARAM_TOKEN_TYPE] }.asString().isEqualTo(TokenType.Bearer.specValue)
                            extracting { it[PARAM_STATE] }.asString().isEqualTo("12345678")
                            extracting { it[PARAM_SCOPE] }.asString().contains("foo", "bar", SCOPE_OPENID)
                            extracting { it[PARAM_EXPIRES_IN] }.asString().satisfies { it.toLong() > 0 }
                        }
                }
            )
        }

        it("acquire only id token from authorize endpoint") {
            OidcImplicitFlow.authorizeEndpointLeg(
                paramModifier = {
                    it.removeIf { p -> p.first == PARAM_RESPONSE_TYPE }
                    it.add(PARAM_RESPONSE_TYPE to ResponseType.IdToken.specValue)
                },
                responseAssertion = {
                    Assertions.assertThat(status()).isEqualTo(HttpStatusCode.Found)
                    Url(headers["Location"]!!).fragment.decodeURLQueryComponent()
                        .split("&")
                        .map { it.split("=").let { p -> Pair(p[0], p[1]) } }
                        .toMap()
                        .let { Assertions.assertThat(it) }
                        .run {
                            extracting { it[PARAM_ACCESS_TOKEN] }.isNull()
                            extracting { it[PARAM_ID_TOKEN] }.asString().isNotEmpty()
                            extracting { it[PARAM_STATE] }.asString().isEqualTo("12345678")
                        }
                }
            )
        }
    }

}) {
    private object OidcImplicitFlow {

        fun authorizeEndpointLeg(
            serverSetup: Routing.() -> Unit = {
                this.apply(KtorServerSupport.testServerSetup)
                Kodein.global.addConfig {
                    bind<ConsentStrategy>(overrides = true) with singleton { OidcConsentStrategy }
                }
            },
            paramModifier: (MutableList<Pair<String, String>>) -> Unit = {},
            responseAssertion: TestApplicationResponse.() -> Unit
        ) {
            KtorServerSupport.flow(
                serverSetup = serverSetup,
                extraConfig = mapOf(
                    "flow.oidc.authorize" to listOf("true"),
                    "flow.oidc.implicit" to listOf("true")
                ),
                requestsAndResponses = listOf(
                    KtorServerSupport.RequestAndResponse(
                        request = {
                            val params = mutableListOf(
                                PARAM_CLIENT_ID to "bar",
                                PARAM_SCOPE to "foo bar $SCOPE_OPENID",
                                PARAM_REDIRECT_URI to "http://localhost:8888/callback",
                                PARAM_RESPONSE_TYPE to "${ResponseType.Token.specValue} ${ResponseType.IdToken.specValue}",
                                PARAM_STATE to "12345678",
                                PARAM_NONCE to "87654321",
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
    }
}