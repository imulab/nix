package io.imulab.nix.oauth

import io.imulab.nix.`when`
import io.imulab.nix.given
import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.then
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.spekframework.spek2.Spek

object OAuthRequestFormSpec: Spek({

    given("a raw form") {
        val rawForm = mutableMapOf(
            Param.clientId to listOf("foo"),
            Param.code to listOf("foo", "bar")
        )

        `when`("parsed into OAuthRequestForm") {
            val oauthRequestForm = OAuthRequestForm(rawForm)

            then("accessing singular param should return value") {
                assertThat(oauthRequestForm.clientId).isEqualTo("foo")
            }

            then("accessing no existing param should return empty string") {
                assertThat(oauthRequestForm.state).isEqualTo("")
            }

            then("accessing duplex param should throw exception") {
                assertThatExceptionOfType(OAuthException::class.java)
                    .isThrownBy { oauthRequestForm.code }
            }
        }
    }
})