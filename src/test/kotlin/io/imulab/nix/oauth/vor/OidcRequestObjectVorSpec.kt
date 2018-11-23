package io.imulab.nix.oauth.vor

import com.github.tomakehurst.wiremock.client.WireMock
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.anyOrNull
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.client.OidcClient
import io.imulab.nix.crypt.JwxProvider
import io.imulab.nix.persistence.Cache
import io.imulab.nix.support.MockServerSupport
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.http.HttpHeaders
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OidcRequestObjectVorSpec: Spek({

    val magicUrl = "http://localhost:31246/request.jwt"

    val magicJwt = "some-jwt-content-that-does-not-matter-in-test"

    val cache = mock<Cache<String, String>> {
        onBlocking { read(magicUrl) } doAnswer {
            println("cache hit")
            magicJwt
        }
        onBlocking { write(any(), any(), anyOrNull()) } doAnswer { iom ->
            println(iom.arguments[2].toString())
            Unit
        }
    }

    val client = mock<OidcClient>()

    val vor = OidcRequestObjectVor(
        jsonWebKeySetVor = mock(),
        cacheCoroutineScope = GlobalScope,
        httpClient = HttpClient(Apache),
        jwxProvider = JwxProvider(),
        requestObjectCache = cache
    )

    describe("resolve already existing request object") {
        it("should return existing request object") {
            val requestObj = GlobalScope.async { vor.resolve(magicJwt, "", async { client }) }
            runBlocking {
                assertThat(requestObj.await()).isEqualTo(magicJwt)
            }
        }
    }

    describe("resolve request object from cache") {
        it("should return request object from cache") {
            val requestObj = GlobalScope.async { vor.resolve("", magicUrl, async { client }) }
            runBlocking {
                assertThat(requestObj.await()).isEqualTo(magicJwt)
            }
        }
    }

    describe("resolve request object from http") {
        beforeGroup {
            MockServerSupport.start()
            MockServerSupport.mock {
                stubFor(
                    WireMock.get(WireMock.urlEqualTo("/request.jwt"))
                        .willReturn(
                            WireMock.aResponse().withStatus(200)
                                .withHeader(HttpHeaders.CacheControl, "public, max-age=31536000")
                                .withBody(magicJwt))
                )
            }
        }

        it("should return request object") {
            val requestObj = GlobalScope.async { vor.resolve("", "${MockServerSupport.url()}/request.jwt", async { client }) }
            runBlocking {
                assertThat(requestObj.await()).isEqualTo(magicJwt)
            }
        }

        afterGroup {
            MockServerSupport.stop()
        }
    }
})