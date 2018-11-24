package io.imulab.nix.oauth.token

import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.crypt.alg.SigningAlgorithm
import io.imulab.nix.oauth.token.strategy.HmacAuthorizeCodeStrategy
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import javax.crypto.KeyGenerator

object HmacAuthorizeCodeStrategySpec: Spek({

    val strategy = HmacAuthorizeCodeStrategy(
        key = KeyGenerator.getInstance("AES").also { it.init(256) }.generateKey(),
        signingAlgorithm = SigningAlgorithm.HS256,
        codeLength = 16
    )

    describe("generate new code") {
        var raw = ""

        it("should generate new code") {
            val code = strategy.generateCode(mock())
            assertThat(code.value).isNotEmpty()
            assertThat(code.signature).isNotEmpty()
            raw = code.toString()
        }

        it("should be able to pass verification") {
            assertThatCode {
                val verified = strategy.verifyCode(mock(), raw)
                assertThat(verified.toString()).isEqualTo(raw)
            }.doesNotThrowAnyException()
        }
    }
})