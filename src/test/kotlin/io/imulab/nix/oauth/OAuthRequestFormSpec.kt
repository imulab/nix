package io.imulab.nix.oauth

import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.reserved.Param
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OAuthRequestFormSpec: Spek({

    describe("getting property through delegate") {
        it("should return value from httpForm when accessing through getter") {
            val form = OAuthRequestForm(httpForm = mutableMapOf(
                Param.clientId to listOf("foo")
            ))
            assertThat(form.clientId).isEqualTo("foo")
        }

        it("should return empty string when accessing a value that does not exist in httpForm") {
            val form = OAuthRequestForm(httpForm = mutableMapOf())
            assertThat(form.clientId).isEqualTo("")
        }

        it("should throw exception when accessing a value that has been provided multiple times") {
            val form = OAuthRequestForm(httpForm = mutableMapOf(
                Param.clientId to listOf("foo", "bar")
            ))
            assertThatExceptionOfType(OAuthException::class.java)
                .isThrownBy { form.clientId }
        }
    }
})