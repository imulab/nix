package deprecated.oauth.vor

import com.github.tomakehurst.wiremock.client.WireMock
import com.nhaarman.mockitokotlin2.any
import com.nhaarman.mockitokotlin2.anyOrNull
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.mock
import deprecated.error.InvalidRequestException
import deprecated.persistence.Cache
import deprecated.support.MockServerSupport
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.http.HttpHeaders
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.*
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object JsonWebKeySetVorSpec : Spek({

    val magicUrl = "http://localhost:31245/jwks.json"

    val magicJwks = """
        { "keys": [
              {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "x5c": [
                  "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
                ],
                "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
                "e": "AQAB",
                "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
                "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"
              }
            ]
        }
    """.trimIndent()

    val cache = mock<Cache<String, String>> {
        onBlocking { read(magicUrl) } doAnswer {
            println("${Thread.currentThread().name} hit")
            magicJwks
        }
        onBlocking { write(any(), any(), anyOrNull()) } doAnswer { iom ->
            println("${Thread.currentThread().name} writeAuthentication")
            println(iom.arguments[2].toString())
            runBlocking { delay(200L) }
        }
    }

    val vor = JsonWebKeySetVor(
        jwksCache = cache,
        httpClient = HttpClient(Apache)
    )

    beforeGroup {
        MockServerSupport.start()
    }

    describe("resolve already existing key set") {
        it("should return json web key set") {
            val jwks = GlobalScope.async { vor.resolve(magicJwks, magicUrl, mock()) }
            runBlocking { assertThat(jwks.await()).isNotNull }
        }
    }

    describe("resolve key set from cache") {
        it("should return json web key set") {
            val jwks = GlobalScope.async { vor.resolve("", magicUrl, mock()) }
            runBlocking { assertThat(jwks.await()).isNotNull }
        }
    }

    describe("resolve key set from http") {
        beforeGroup {
            MockServerSupport.mock {
                stubFor(
                    WireMock.get(WireMock.urlEqualTo("/jwks.json"))
                        .willReturn(
                            WireMock.aResponse().withStatus(200)
                                .withHeader(HttpHeaders.CacheControl, "public, max-age=31536000")
                                .withBody(magicJwks))
                )
                stubFor(
                    WireMock.get(WireMock.urlEqualTo("/jwks.bad.json"))
                        .willReturn(
                            WireMock.aResponse().withStatus(404))
                )
            }
        }

        it("should return json web key set") {
            val jwks = GlobalScope.async { vor.resolve("", "${MockServerSupport.url()}/jwks.json", mock()) }
            runBlocking {
                assertThat(jwks.await()).isNotNull
            }
        }

        it("should throw exception when not 200") {
            val jwks = GlobalScope.async { vor.resolve("", "${MockServerSupport.url()}/jwks.bad.json", mock()) }
            assertThatExceptionOfType(InvalidRequestException::class.java)
                .isThrownBy {
                    runBlocking { jwks.await() }
                }
        }

        afterGroup {
            MockServerSupport.reset()
        }
    }

    afterGroup {
        MockServerSupport.stop()
    }
})