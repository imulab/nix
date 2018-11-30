package io.imulab.nix.oauth.validation

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oauth.OAuthAuthorizeRequest
import io.imulab.nix.oauth.OAuthException
import io.imulab.nix.oauth.OAuthRequest
import io.imulab.nix.oauth.RedirectUriValidator
import io.imulab.nix.oauth.client.OAuthClient
import org.assertj.core.api.Assertions
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object RedirectUriValidatorSpec: Spek({

    fun withUri(v: String): OAuthRequest {
        val client: OAuthClient = mock {
            onGeneric { redirectUris } doReturn setOf(v)
        }
        return mock<OAuthAuthorizeRequest> {
            onGeneric { redirectUri } doReturn v
            onGeneric { this.client } doReturn client
        }
    }


    describe("validation") {

        it("https redirect uri should be valid") {
            Assertions.assertThatCode {
                RedirectUriValidator.validate(withUri("https://test.com/app"))
            }.doesNotThrowAnyException()
        }

        it("http localhost or 127.0.0.1 uri should be valid") {
            Assertions.assertThatCode {
                RedirectUriValidator.validate(withUri("http://localhost:8080/app"))
            }.doesNotThrowAnyException()

            Assertions.assertThatCode {
                RedirectUriValidator.validate(withUri("http://127.0.0.1:8080/app"))
            }.doesNotThrowAnyException()
        }

        it("app redirect uri should be valid") {
            Assertions.assertThatCode {
                RedirectUriValidator.validate(withUri("app://deep/link"))
            }.doesNotThrowAnyException()
        }

        it("non-localhost http redirect url is not valid") {
            Assertions.assertThatExceptionOfType(OAuthException::class.java)
                .isThrownBy {
                    RedirectUriValidator.validate(withUri("http://test.com"))
                }
        }

        it("uri with fragment is not valid") {
            Assertions.assertThatExceptionOfType(OAuthException::class.java)
                .isThrownBy {
                    RedirectUriValidator.validate(withUri("https://test.com?foo=bar#something"))
                }
        }
    }
})