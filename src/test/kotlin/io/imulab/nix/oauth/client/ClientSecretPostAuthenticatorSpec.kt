package io.imulab.nix.oauth.client

import com.nhaarman.mockitokotlin2.argThat
import com.nhaarman.mockitokotlin2.doAnswer
import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import io.imulab.nix.`when`
import io.imulab.nix.given
import io.imulab.nix.oauth.client.ClientSecretPostAuthenticatorSpec.requestWithCredential
import io.imulab.nix.oauth.client.authn.ClientSecretPostAuthenticator
import io.imulab.nix.oauth.client.pwd.BCryptPasswordEncoder
import io.imulab.nix.oauth.error.InvalidClient
import io.imulab.nix.oauth.error.OAuthException
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.then
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.spekframework.spek2.Spek

object ClientSecretPostAuthenticatorSpec: Spek({

    given("a properly configured authenticator") {
        val authenticator = Given().authenticator

        `when`("a request is made with valid credential") {
            val request = requestWithCredential("foo", "s3cret")

            then("authentication should pass and return the client") {
                runBlocking {
                    assertThat(authenticator.authenticate(request)).extracting {
                        it.id
                    }.isEqualTo("foo")
                }
            }
        }

        `when`("a request is made with bad credential") {
            val request = requestWithCredential("foo", "invalid")

            then("authentication should raise an error") {
                assertThatExceptionOfType(OAuthException::class.java)
                    .isThrownBy { runBlocking { authenticator.authenticate(request) } }
            }
        }

        `when`("a request with made with unknown client") {
            val request = requestWithCredential("bar", "s3cret")

            then("authentication should raise an error") {
                assertThatExceptionOfType(OAuthException::class.java)
                    .isThrownBy { runBlocking { authenticator.authenticate(request) } }
            }
        }
    }
}) {
    class Given {
        private val encoder = BCryptPasswordEncoder()
        private val client = mock<OAuthClient> {
            onGeneric { it.id } doReturn "foo"
            onGeneric { it.secret } doReturn encoder.encode("s3cret").toByteArray()
        }
        private val clientLookup = mock<ClientLookup> {
            onBlocking { find("foo") } doReturn client
            onBlocking { find(argThat { this != "foo" }) } doAnswer { throw InvalidClient.unknown() }
        }
        val authenticator = ClientSecretPostAuthenticator(clientLookup, encoder)
    }

    fun requestWithCredential(username: String, password: String): OAuthRequestForm {
        return OAuthRequestForm(
            httpForm = mutableMapOf(
                Param.clientId to listOf(username),
                Param.clientSecret to listOf(password)
            )
        )
    }
}