package io.imulab.nix.oauth.response

import io.imulab.nix.oauth.putIfNotEmpty
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oauth.reserved.space

open class TokenEndpointResponse(
    override var accessToken: String = "",
    override var tokenType: String = "",
    override var expiresIn: Long = 0,
    override var refreshToken: String = "",
    override var scope: Set<String> = emptySet(),
    override var state: String = ""
) : AccessTokenResponse, OAuthResponse {

    override val status: Int
        get() = 200
    override val headers: Map<String, String>
        get() = mapOf(
            "Cache-Control" to "no-store",
            "Pragma" to "no-cache"
        )
    override val data: Map<String, String>
        get() {
            val m = mutableMapOf<String, String>()
            m.putIfNotEmpty(Param.accessToken, accessToken)
            m.putIfNotEmpty(Param.tokenType, tokenType)
            m.putIfNotEmpty(Param.expiresIn, if (expiresIn > 0) expiresIn.toString() else "")
            m.putIfNotEmpty(Param.refreshToken, refreshToken)
            m.putIfNotEmpty(Param.state, state)
            m.putIfNotEmpty(Param.scope, scope.joinToString(space).trim())
            return m
        }
}