package io.imulab.nix.oauth.client

import com.nhaarman.mockitokotlin2.argThat
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.oauth.reserved.Header
import io.imulab.nix.oauth.InvalidClient
import io.imulab.nix.oauth.OAuthException
import io.imulab.nix.oauth.OAuthRequestForm
import io.imulab.nix.oauth.client.authn.ClientSecretBasicAuthenticator
import io.imulab.nix.oauth.client.pwd.BCryptPasswordEncoder
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.nio.charset.StandardCharsets
import java.util.*

object ClientSecretBasicAuthenticatorSpec: Spek({

    val authenticator = ClientSecretBasicAuthenticator(
        lookup = BOM.clientLookup,
        passwordEncoder = BOM.pwdEncoder
    )

    describe("authenticate client") {
        it("should return client when credential is sound") {
            val goodHeader = "Basic " + Base64.getEncoder().encodeToString("foo:s3cret".toByteArray())
            val form = OAuthRequestForm(httpForm = mutableMapOf(
                Header.authorization to listOf(goodHeader)
            ))

            runBlocking {
                assertThat(authenticator.authenticate(form)).extracting {
                    it.id
                }.isEqualTo("foo")
            }
        }

        it("should raise invalid_client error when credential is bad") {
            val badHeader = "Basic " + Base64.getEncoder().encodeToString("foo:bad".toByteArray())
            val form = OAuthRequestForm(httpForm = mutableMapOf(
                Header.authorization to listOf(badHeader)
            ))

            assertThatExceptionOfType(OAuthException::class.java)
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