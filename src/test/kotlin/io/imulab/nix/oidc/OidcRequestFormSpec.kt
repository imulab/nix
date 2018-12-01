package io.imulab.nix.oidc

import io.imulab.nix.oauth.OAuthException
import io.imulab.nix.oauth.reserved.Param
import org.assertj.core.api.Assertions
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object OidcRequestFormSpec: Spek({

    describe("getting property through delegate") {
        it("should return value from httpForm when accessing through getter") {
            val form = OidcRequestForm(httpForm = mutableMapOf(
                OidcParam.nonce to listOf("12345678"),
                Param.clientId to listOf("foo")
            ))
            Assertions.assertThat(form.nonce).isEqualTo("12345678")
            Assertions.assertThat(form.clientId).isEqualTo("foo")
        }

        it("should return empty string when accessing a value that does not exist in httpForm") {
            val form = OidcRequestForm(httpForm = mutableMapOf())
            Assertions.assertThat(form.clientId).isEqualTo("")
            Assertions.assertThat(form.nonce).isEqualTo("")
        }

        it("should throw exception when accessing a value that has been provided multiple times") {
            val form = OidcRequestForm(httpForm = mutableMapOf(
                OidcParam.nonce to listOf("foo", "bar")
            ))
            Assertions.assertThatExceptionOfType(OAuthException::class.java)
                .isThrownBy { form.nonce }
        }
    }
})