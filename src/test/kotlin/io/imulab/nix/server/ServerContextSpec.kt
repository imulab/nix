package io.imulab.nix.server

import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.server.config.ServerContext
import io.ktor.config.MapApplicationConfig
import io.ktor.util.KtorExperimentalAPI
import org.assertj.core.api.Assertions.assertThat
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe

@UseExperimental(KtorExperimentalAPI::class)
object ServerContextSpec : Spek({

    describe("read property from application config") {

        val applicationConfig = MapApplicationConfig().also {
            it.put("nix.endpoint.issuer", "https://nix.com")
            it.put("nix.oauth.responseTypes", listOf("code", "token", "id_token"))
            it.put("nix.oauth.stateEntropy", "8")
            it.put("nix.requestObject.supportRequestParameter", "true")
        }

        val serverContext = ServerContext(
            config = applicationConfig,
            jsonWebKeySetRepository = mock()
        )

        it("should be able to read string property") {
            assertThat(serverContext.issuer).isEqualTo("https://nix.com")
        }

        it("should be able to read list property") {
            assertThat(serverContext.responseTypesSupported).contains("code", "token", "id_token")
        }

        it("should be able to read int property") {
            assertThat(serverContext.stateEntropy).isEqualTo(8)
        }

        it("should be able to read boolean property") {
            assertThat(serverContext.requestParameterSupported).isTrue()
        }
    }
})