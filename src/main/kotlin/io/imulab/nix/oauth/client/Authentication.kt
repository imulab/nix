package io.imulab.nix.oauth.client

import io.imulab.nix.oauth.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * Provides authentication functions.
 */
interface ClientAuthenticator {

    /**
     * Probe method that returns true if this authenticator can process
     * an authentication method identifier by [method].
     */
    fun supports(method: String): Boolean

    /**
     * Authenticates the client using the provided credentials in the [form].
     * If authentication is successful, returns the [OAuthClient] that just passed
     * authentication. If authentication failed, raise invalid_client error.
     */
    suspend fun authenticate(form: OAuthRequestForm): OAuthClient
}

/**
 * Main point of entry client authenticator that delegate work to a list of [authenticators]
 * depending on the supported method. If no authenticator was able to take on work, it
 * raises server_error.
 */
class ClientAuthenticators(
    private val authenticators: List<ClientAuthenticator>,
    private val defaultMethod: String = AuthenticationMethod.clientSecretPost,
    private val methodFinder: suspend (OAuthRequestForm) -> String = { defaultMethod }
) {

    suspend fun authenticate(form: OAuthRequestForm): OAuthClient {
        val method = methodFinder(form)
        return authenticators.find { it.supports(method) }?.authenticate(form)
            ?: throw ServerError.internal("No client authenticators configured for method <$method>.")
    }
}

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

    private val unauthorizedError = InvalidClient.unauthorized(AuthenticationMethod.clientSecretBasic)

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

/**
 * Implementation of [ClientAuthenticator] that supports client_secret_post method where
 * client submits client_id and client_secret parameters in an HTTP Form POST.
 */
class ClientSecretPostAuthenticator(
    private val lookup: ClientLookup,
    private val passwordEncoder: PasswordEncoder
): ClientAuthenticator {

    override fun supports(method: String): Boolean =
        method == AuthenticationMethod.clientSecretPost

    override suspend fun authenticate(form: OAuthRequestForm): OAuthClient {
        if (form.clientId.isEmpty() || form.clientSecret.isEmpty())
            throw InvalidClient.authenticationRequired()

        val client = withContext(Dispatchers.IO) {
            run { lookup.find(form.clientId) }
        }
        if (!passwordEncoder.matches(form.clientSecret, client.secret.toString(StandardCharsets.UTF_8)))
            throw InvalidClient.authenticationFailed()

        return client
    }
}