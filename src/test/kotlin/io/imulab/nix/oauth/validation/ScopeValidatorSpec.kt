package io.imulab.nix.oauth.validation

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oauth.OAuthAuthorizeRequest
import io.imulab.nix.oauth.OAuthException
import io.imulab.nix.oauth.OAuthRequest
import io.imulab.nix.oauth.ScopeValidator
import io.imulab.nix.oauth.client.OAuthClient
import org.assertj.core.api.Assertions
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object ScopeValidatorSpec : Spek({

    fun withScopes(vararg scopes: String): OAuthRequest {
        val client = mock<OAuthClient> {
            onGeneric { this.scopes } doReturn setOf("foo", "bar")
        }
        return mock<OAuthAuthorizeRequest> {
            onGeneric { this.scopes } doReturn scopes.toSet()
            onGeneric { this.client } doReturn client
        }
    }

    describe("validation") {
        it("valid scopes should pass") {
            Assertions.assertThatCode {
                ScopeValidator.validate(withScopes("foo", "bar"))
            }.doesNotThrowAnyException()
        }

        it("malformed scopes should fail") {
            Assertions.assertThatExceptionOfType(OAuthException::class.java)
                .isThrownBy {
                    ScopeValidator.validate(withScopes("foo", "\"foo\""))
                }
        }
    }
})