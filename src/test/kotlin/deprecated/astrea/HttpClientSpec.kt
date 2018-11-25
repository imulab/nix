package deprecated.astrea

import com.github.tomakehurst.wiremock.client.WireMock.*
import deprecated.support.MockServerSupport
import org.assertj.core.api.Assertions.assertThat
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.nio.charset.StandardCharsets

object HttpClientSpec: Spek({

    beforeGroup {
        require(MockServerSupport.start())
    }

    describe("http client") {
        beforeGroup {
            MockServerSupport.mock {
                stubFor(
                    get(urlEqualTo("/hello"))
                        .willReturn(aResponse().withStatus(200)
                            .withBody("hello world"))
                )
            }
        }

        it("""
            should match status code
        """.trimIndent()) {
            assertThat(HttpClient.get("${MockServerSupport.url()}/hello").statusCode())
                .isEqualTo(200)
        }

        it("""
            should match body
        """.trimIndent()) {
            assertThat(HttpClient.get("${MockServerSupport.url()}/hello").body())
                .isEqualTo("hello world".toByteArray(StandardCharsets.UTF_8))
        }

        afterGroup {
            MockServerSupport.reset()
        }
    }

    afterGroup {
        MockServerSupport.stop()
    }
})