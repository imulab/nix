package io.imulab.nix.oauth.client.authn

import io.imulab.nix.oauth.AuthenticationMethod
import io.imulab.nix.oauth.InvalidClient
import io.imulab.nix.oauth.OAuthRequestForm
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.client.pwd.PasswordEncoder
import io.imulab.nix.oauth.colon
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * Implementation of [ClientAuthenticator] that supports client_secret_basic where
 * client submits its credentials in the form Base64(client_id:client_secret) as the
 * value of HTTP Basic authentication.
 */
class ClientSecretBasicAuthenticator(
    private val lookup: ClientLookup,
    private val passwordEncoder: PasswordEncoder,
    private val decoder: Base64.Decoder = Base64.getDecoder()
): ClientAuthenticator {

    private val unauthorizedError =
        InvalidClient.unauthorized(AuthenticationMethod.clientSecretBasic)

    override fun supports(method: String): Boolean =
        method == AuthenticationMethod.clientSecretBasic

    override suspend fun authenticate(form: OAuthRequestForm): OAuthClient {
        val header = form.authorizationHeader
        when {
            header.isEmpty() ->
                throw unauthorizedError
            !header.startsWith("Basic ") ->
                throw unauthorizedError
        }

        val clientId: String
        val clientSecret: String
        try {
            val parts = String(decoder.decode(header.removePrefix("Basic ")), StandardCharsets.UTF_8)
                .split(colon)
            when {
                parts.size != 2 -> throw unauthorizedError
                parts[0].isEmpty() -> throw unauthorizedError
                parts[1].isEmpty() -> throw unauthorizedError
                else -> {
                    clientId = parts[0]
                    clientSecret = parts[1]
                }
            }
        } catch (_: IllegalArgumentException) {
            throw unauthorizedError
        }

        assert(clientId.isNotEmpty())
        assert(clientSecret.isNotEmpty())

        val client = withContext(Dispatchers.IO) {
            run { lookup.find(clientId) }
        }
        if (!passwordEncoder.matches(clientSecret, client.secret.toString(StandardCharsets.UTF_8)))
            throw unauthorizedError

        return client
    }
}