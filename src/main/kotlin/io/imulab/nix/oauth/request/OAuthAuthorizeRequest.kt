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
    val scopes: Set<String>,
    val state: String,
    session: OAuthSession = OAuthSession()
) : OAuthRequest(client = client, session = session) {

    /**
     * Convenience method to grant a scope. The granted scope must be in the requested [scopes].
     */
    fun grantScope(scope: String) {
        if (scopes.contains(scope))
            session.grantedScopes.add(scope)
    }

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