package io.imulab.nix.oauth.request

import io.imulab.nix.client.metadata.ResponseType
import io.imulab.nix.support.asValid

interface AuthorizeRequest: OidcRequest {

    val responseTypes: Set<ResponseType>

    val redirectUri: String

    val state: String

    fun setHandled(responseType: ResponseType)

    fun hasHandledAll(): Boolean
}