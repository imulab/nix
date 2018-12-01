package io.imulab.nix.oauth.validation

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oauth.*
import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.request.OAuthRequest
import org.assertj.core.api.Assertions
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

object StateValidatorSpec : Spek({

    fun withState(v: String): OAuthRequest {
        return mock<OAuthAuthorizeRequest> {
            onGeneric { state } doReturn v
        }
    }

    describe("validation") {

        val context: OAuthContext = mock {
            onGeneric { stateEntropy } doReturn 8
        }

        it("sufficient entropy should pass") {
            Assertions.assertThatCode {
                StateValidator(context).validate(withState("12345678"))
            }.doesNotThrowAnyException()
        }

        it("no state should pass (because it's optional)") {
            Assertions.assertThatCode {
                StateValidator(context).validate(withState(""))
            }.doesNotThrowAnyException()
        }

        it("insufficient entropy should fail") {
            Assertions.assertThatExceptionOfType(OAuthException::class.java)
                .isThrownBy {
                    StateValidator(context).validate(withState("123"))
                }
        }
    }
})