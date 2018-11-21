package io.imulab.nix.oauth.response

import io.imulab.nix.constant.Param

interface AccessTokenAware : OAuthResponse {

    var accessToken: String

    var expiresIn: Long

    var tokenType: String

    override fun getStatus(): Int = 200

    override fun getExtraHeaders(): Map<String, String> = emptyMap()

    override fun getParameters(): Map<String, String> = mapOf(
        Param.ACCESS_TOKEN to accessToken,
        Param.EXPIRES_IN to (if (expiresIn == 0L) "" else expiresIn.toString()),
        Param.TOKEN_TYPE to tokenType
    )
}