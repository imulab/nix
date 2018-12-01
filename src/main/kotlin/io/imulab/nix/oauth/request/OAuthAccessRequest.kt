package io.imulab.nix.oauth.request

import io.imulab.nix.oauth.client.OAuthClient
import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.reserved.Param

/**
 * An OAuth access request
 */
open class OAuthAccessRequest(
    val grantTypes: Set<String>,
    val code: String,
    val redirectUri: String,
    client: OAuthClient
) : OAuthRequest(client = client) {

    class Builder(
        var grantTypes: MutableSet<String> = mutableSetOf(),
        var code: String = "",
        var redirectUri: String = "",
        var client: OAuthClient? = null
    ) {

        fun build(): OAuthAccessRequest {
            if (grantTypes.isEmpty())
                throw InvalidRequest.required(Param.grantType)
            if (code.isEmpty())
                throw InvalidRequest.required(Param.code)
            if (redirectUri.isEmpty())
                throw InvalidRequest.required(Param.redirectUri)

            checkNotNull(client)

            return OAuthAccessRequest(
                grantTypes = grantTypes.toSet(),
                code = code,
                redirectUri = redirectUri,
                client = client!!
            )
        }
    }
}