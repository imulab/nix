package io.imulab.nix.oauth.request

import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.reserved.Param

/**
 * An OAuthConfig access request
 */
open class OAuthAccessRequest(
    val grantTypes: Set<String>,
    val code: String,
    val refreshToken: String,
    val redirectUri: String,
    client: OAuthClient,
    scopes: Set<String> = emptySet()
) : OAuthRequest(client = client, scopes = scopes) {

    class Builder(
        var grantTypes: MutableSet<String> = mutableSetOf(),
        var code: String = "",
        var refreshToken: String = "",
        var redirectUri: String = "",
        var scopes: MutableSet<String> = mutableSetOf(),
        var client: OAuthClient? = null
    ) {

        fun build(): OAuthAccessRequest {
            if (grantTypes.isEmpty())
                throw InvalidRequest.required(Param.grantType)
            if (redirectUri.isEmpty())
                throw InvalidRequest.required(Param.redirectUri)

            checkNotNull(client)

            return OAuthAccessRequest(
                grantTypes = grantTypes.toSet(),
                code = code,
                refreshToken = refreshToken,
                scopes = scopes,
                redirectUri = redirectUri,
                client = client!!
            )
        }
    }
}