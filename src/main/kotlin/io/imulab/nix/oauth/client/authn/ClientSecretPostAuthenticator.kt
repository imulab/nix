package io.imulab.nix.oauth.client.authn

import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.client.pwd.PasswordEncoder
import io.imulab.nix.oauth.error.InvalidClient
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oauth.reserved.AuthenticationMethod
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets

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