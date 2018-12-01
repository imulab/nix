package io.imulab.nix.oauth.client

import com.nhaarman.mockitokotlin2.argThat
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oauth.error.InvalidClient
import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.OAuthRequestForm
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oauth.client.authn.ClientSecretPostAuthenticator
import io.imulab.nix.oauth.client.pwd.BCryptPasswordEncoder
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.nio.charset.StandardCharsets

object ClientSecretPostAuthenticatorSpec: Spek({

    val authenticator = ClientSecretPostAuthenticator(
        lookup = BOM.clientLookup,
        passwordEncoder = BOM.pwdEncoder
    )

    describe("authenticate client") {
        it("should return client when credential is sound") {
            val form = OAuthRequestForm(httpForm = mutableMapOf(
                Param.clientId to listOf("foo"),
                Param.clientSecret to listOf("s3cret")
            ))

            runBlocking {
                Assertions.assertThat(authenticator.authenticate(form)).extracting {
                    it.id
                }.isEqualTo("foo")
            }
        }

        it("should raise invalid_client error when credential is bad") {
            val form = OAuthRequestForm(httpForm = mutableMapOf(
                Param.clientId to listOf("foo"),
                Param.clientSecret to listOf("bad")
            ))

            Assertions.assertThatExceptionOfType(OAuthException::class.java)
                .isThrownBy {
                    runBlocking { authenticator.authenticate(form) }
                }
        }
    }
}) {
    private object BOM {
        val pwdEncoder = BCryptPasswordEncoder()

        val fooClient = mock<OAuthClient> {
            onGeneric { it.id } doReturn "foo"
            onGeneric { it.secret } doReturn pwdEncoder.encode("s3cret").toByteArray(StandardCharsets.UTF_8)
        }

        val clientLookup = mock<ClientLookup> {
            onBlocking { find("foo") } doReturn fooClient
            onBlocking { find(argThat { this != "foo" }) } doAnswer {
                println(it.arguments[0])
                throw InvalidClient.unknown()
            }
        }
    }
}