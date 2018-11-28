package io.imulab.nix.oidc

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.*
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.nhaarman.mockitokotlin2.argThat
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oidc.client.OidcClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.jose4j.jwk.JsonWebKeySet
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object JsonWebKeySetStrategySpec : Spek({

    val strategy = JsonWebKeySetStrategy(
        jsonWebKeySetRepository = BOM.repository,
        httpClient = BOM.httpClient
    )

    fun expectMagicJwks(client: OidcClient) {
        assertThat(runBlocking { strategy.resolveKeySet(client) })
            .extracting { it.jsonWebKeys.firstOrNull()?.keyId }
            .isEqualTo("NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg")
    }

    describe("resolve jwks locally") {
        it("should return jwks value if registered by client") {
            expectMagicJwks(mock {
                onGeneric { jwks } doReturn BOM.magicJwks
                onGeneric { jwksUri } doReturn ""
            })
        }

        it("should return jwks_uri content from repository") {
            expectMagicJwks(mock {
                onGeneric { jwks } doReturn ""
                onGeneric { jwksUri } doReturn "http://localhost:8080/saved.jwks"
            })
        }
    }

    describe("resolve jwks") {

        val mockJwksServer = WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort())

        beforeGroup {
            mockJwksServer.start()
            mockJwksServer.stubFor(
                get(urlEqualTo("/test.jwks"))
                    .willReturn(aResponse().withStatus(200).withBody(BOM.magicJwks))
            )
        }

        it("should return jwks_uri content from remote") {
            expectMagicJwks(mock {
                onGeneric { jwks } doReturn ""
                onGeneric { jwksUri } doReturn "${mockJwksServer.baseUrl()}/test.jwks"
            })

        }

        afterGroup {
            mockJwksServer.stop()
        }
    }

}) {
    private object BOM {
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
        val httpClient = HttpClient(Apache)
        val repository = mock<JsonWebKeySetRepository> {
            onBlocking { getClientJsonWebKeySet(argThat { this.endsWith("saved.jwks") }) } doReturn JsonWebKeySet(magicJwks)
        }
    }
}