package io.imulab.nix.astrea

import io.imulab.astrea.spi.http.singleValue
import io.imulab.nix.support.KtorServerSupport
import io.ktor.application.call
import io.ktor.http.*
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.server.testing.setBody
import org.assertj.core.api.Assertions
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object HttpRequestSpec: Spek({

    describe("get request") {
        it("""
            should have correct method, form and header
        """.trimIndent()) {
            KtorServerSupport.oneShot(clientSetup = {
                method = HttpMethod.Get
                uri = "/get?" + listOf("k1" to "v1", "k2" to "v2 v3").formUrlEncode()
                addHeader("FOO", "BAR")
            }, serverSetup = {
                get("/get") {
                    HttpRequest(this.call).apply {
                        Assertions.assertThat(method()).isEqualTo(HttpMethod.Get.value)
                        Assertions.assertThat(getForm().singleValue("k1")).isEqualTo("v1")
                        Assertions.assertThat(getForm().singleValue("k2")).isEqualTo("v2 v3")
                        Assertions.assertThat(getHeader("FOO")).isEqualTo("BAR")
                    }
                    call.respond("OK")
                }
            })
        }
    }

    describe("post request") {
        it("""
            should have correct method, form and header
        """.trimIndent()) {
            KtorServerSupport.oneShot(clientSetup = {
                method = HttpMethod.Post
                uri = "/post"
                addHeader(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                addHeader("FOO", "BAR")
                setBody(listOf("k1" to "v1", "k2" to "v2 v3").formUrlEncode())
            }, serverSetup = {
                post("/post") {
                    HttpRequest(this.call).apply {
                        Assertions.assertThat(method()).isEqualTo(HttpMethod.Post.value)
                        Assertions.assertThat(getForm().singleValue("k1")).isEqualTo("v1")
                        Assertions.assertThat(getForm().singleValue("k2")).isEqualTo("v2 v3")
                        Assertions.assertThat(getHeader("FOO")).isEqualTo("BAR")
                    }
                    call.respond("OK")
                }
            })
        }
    }
})