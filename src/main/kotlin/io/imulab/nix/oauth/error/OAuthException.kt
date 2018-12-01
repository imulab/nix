package io.imulab.nix.oauth.error

import io.imulab.nix.oauth.response.OAuthResponse
import io.imulab.nix.oauth.reserved.Param

class OAuthException(
    override val status: Int,
    val error: String,
    private val description: String,
    override val headers: Map<String, String> = emptyMap()
) : RuntimeException("$error: $description"), OAuthResponse {

    override val data: Map<String, String>
        get() = mapOf(
            Param.error to error,
            Param.errorDescription to description
        )
}