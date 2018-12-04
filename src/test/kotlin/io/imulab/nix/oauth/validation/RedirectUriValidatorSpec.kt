package io.imulab.nix.oauth.validation

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.`when`
import io.imulab.nix.given
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.RedirectUriValidatorSpec.requestWithUri
import io.imulab.nix.then
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.spekframework.spek2.Spek

object RedirectUriValidatorSpec: Spek({

    given("redirect uri validator") {
        val validator = RedirectUriValidator

        `when`("request made with good redirect uri") {
            val request = requestWithUri("https://test.com/app")

            then("validation should pass") {
                assertThatCode { validator.validate(request) }.doesNotThrowAnyException()
            }
        }

        `when`("request made with localhost uri") {
            val request = requestWithUri("http://localhost:8080/app")

            then("validation should pass") {
                assertThatCode { validator.validate(request) }.doesNotThrowAnyException()
            }
        }

        `when`("request made with 127.0.0.1 uri") {
            val request = requestWithUri("http://127.0.0.1:8080/app")

            then("validation should pass") {
                assertThatCode { validator.validate(request) }.doesNotThrowAnyException()
            }
        }

        `when`("request made with app uri") {
            val request = requestWithUri("app://deep/link")

            then("validation should pass") {
                assertThatCode { validator.validate(request) }.doesNotThrowAnyException()
            }
        }

        `when`("request made with http (non-localhost) uri") {
            val request = requestWithUri("http://test.com")

            then("validation should fail") {
                assertThatExceptionOfType(OAuthException::class.java)
                    .isThrownBy { validator.validate(request) }
            }
        }

        `when`("request made with url with fragment") {
            val request = requestWithUri("https://test.com?foo=bar#something")
            then("validation should fail") {
                assertThatExceptionOfType(OAuthException::class.java)
                    .isThrownBy { validator.validate(request) }
            }
        }
    }
}) {
    fun requestWithUri(v: String): OAuthRequest {
        val client: OAuthClient = mock {
            onGeneric { redirectUris } doReturn setOf(v)
        }
        return mock<OAuthAuthorizeRequest> {
            onGeneric { redirectUri } doReturn v
            onGeneric { this.client } doReturn client
        }
    }
}