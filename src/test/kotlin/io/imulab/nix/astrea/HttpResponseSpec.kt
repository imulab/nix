package io.imulab.nix.astrea

import io.imulab.astrea.spi.http.HttpResponseWriter
import io.imulab.nix.support.KtorServerSupport
import io.ktor.application.call
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.routing.get
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.*
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.nio.charset.StandardCharsets

object HttpResponseSpec: Spek({

    describe("response") {
        it("""
            should have correct status, header and body
        """.trimIndent()) {
            KtorServerSupport.test(
                clientSetup = {
                    method = HttpMethod.Get
                    uri = "/get"
                },
                serverSetup = {
                    get("/get") {
                        val response: HttpResponseWriter = HttpResponse(call)
                        response.setStatus(200)
                        response.setHeader("FOO", "BAR")
                        response.writeBody("hello world".toByteArray(StandardCharsets.UTF_8))
                    }
                },
                responseAssertion = {
                    assertThat(status()).isEqualTo(HttpStatusCode.OK)
                    assertThat(headers["FOO"]).isEqualTo("BAR")
                    assertThat(content).isEqualTo("hello world")
                })
        }
    }
})