package io.imulab.nix.oauth.token

import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.crypt.alg.SigningAlgorithm
import io.imulab.nix.oauth.token.strategy.HmacRefreshTokenStrategy
import org.assertj.core.api.Assertions
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import javax.crypto.KeyGenerator

object HmacRefreshTokenStrategySpec: Spek({

    val strategy = HmacRefreshTokenStrategy(
        key = KeyGenerator.getInstance("AES").also { it.init(256) }.generateKey(),
        signingAlgorithm = SigningAlgorithm.HS512,
        codeLength = 32
    )

    describe("generate new token") {
        var raw = ""

        it("should generate new token") {
            val token = strategy.generateToken(mock())
            println(token)
            Assertions.assertThat(token.value).isNotEmpty()
            Assertions.assertThat(token.signature).isNotEmpty()
            raw = token.toString()
        }

        it("should be able to pass verification") {
            Assertions.assertThatCode {
                val verified = strategy.verifyToken(mock(), raw)
                Assertions.assertThat(verified.toString()).isEqualTo(raw)
            }.doesNotThrowAnyException()
        }
    }
})