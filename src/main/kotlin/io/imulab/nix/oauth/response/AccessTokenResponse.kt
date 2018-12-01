package io.imulab.nix.oauth.response

import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oauth.reserved.space

/**
 * Response that return an access token, and optionally refresh token.
 */
data class AccessTokenResponse(
    /**
     * The access token issued by the authorization server.
     */
    var accessToken: String = "",
    /**
     * The type of the token issued.
     */
    var tokenType: String = "",
    /**
     * The lifetime in seconds of the access token.
     */
    var expiresIn: Long? = null,
    /**
     * The refresh token issued by the authorization server, if any.
     */
    var refreshToken: String? = null,
    /**
     * The array of granted scopes, if different with the requested values.
     */
    var scope: Set<String>? = null,
    /**
     * The state from the authorize request, if any.
     */
    var state: String? = null
) : OAuthResponse {
    override val status: Int
        get() = 200
    override val headers: Map<String, String>
        get() = mapOf(
            "Cache-Control" to "no-store",
            "Pragma" to "no-cache"
        )
    override val data: Map<String, String>
        get() {
            check(accessToken.isNotEmpty())
            check(tokenType.isNotEmpty())

            return mutableMapOf(
                Param.accessToken to accessToken,
                Param.tokenType to tokenType
            ).also {
                if (expiresIn != null)
                    it[Param.expiresIn] = expiresIn!!.toString()
                if (!refreshToken.isNullOrBlank())
                    it[Param.refreshToken] = refreshToken!!
                if (!scope.isNullOrEmpty())
                    it[Param.scope] = scope!!.joinToString(separator = space)
                if (!state.isNullOrBlank())
                    it[Param.state] = state!!
            }
        }
}