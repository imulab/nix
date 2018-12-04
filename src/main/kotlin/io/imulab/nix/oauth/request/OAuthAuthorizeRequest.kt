package io.imulab.nix.oauth.request

import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.reserved.Param

/**
 * An OAuthConfig authorize request
 */
open class OAuthAuthorizeRequest(
    client: OAuthClient,
    val responseTypes: Set<String>,
    val redirectUri: String,
    val state: String,
    scopes: Set<String>,
    session: OAuthSession = OAuthSession()
) : OAuthRequest(client = client, scopes = scopes, session = session) {

    class Builder(
        var responseTypes: MutableSet<String> = mutableSetOf(),
        var redirectUri: String = "",
        var scopes: MutableSet<String> = mutableSetOf(),
        var state: String = "",
        var client: OAuthClient? = null
    ) {

        fun build(): OAuthAuthorizeRequest {
            if (responseTypes.isEmpty())
                throw InvalidRequest.required(Param.responseType)

            check(redirectUri.isNotEmpty())
            checkNotNull(client)

            return OAuthAuthorizeRequest(
                client = client!!,
                responseTypes = responseTypes.toSet(),
                redirectUri = redirectUri,
                scopes = scopes,
                state = state
            )
        }
    }
}