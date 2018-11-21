package io.imulab.nix.oauth.request

import io.imulab.nix.client.metadata.ResponseType
import io.imulab.nix.support.asValid

interface AuthorizeRequest: OAuthRequest {

    val responseTypes: Set<ResponseType>

    val redirectUri: String

    val state: String

    fun setHandled(responseType: ResponseType)

    fun hasHandledAll(): Boolean

    /**
     * Returns the effective redirect uri that will be used in this request.
     */
    fun getEffectiveRedirectUri(): String {
        return if (redirectUri.isBlank()) {
            when (client.redirectUris.size) {
                1 -> client.redirectUris[0].asValid()
                0 -> TODO("no redirect uri")
                else -> TODO("multiple redirect uri")
            }
        } else {
            if (client.redirectUris.contains(redirectUri))
                redirectUri.asValid()
            else
                TODO("unregistered redirect uri")
        }
    }
}