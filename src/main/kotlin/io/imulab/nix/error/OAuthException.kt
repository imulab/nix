package io.imulab.nix.error

import io.imulab.nix.constant.Param
import io.imulab.nix.oauth.response.OAuthResponse

abstract class OAuthException(
    private val code: String,
    private val subCode: String,
    private val description: String
): RuntimeException(description), OAuthResponse {

    override fun getExtraHeaders(): Map<String, String> = emptyMap()

    override fun getParameters(): Map<String, String> = mapOf(
        Param.ERROR to code,
        Param.ERROR_CODE to subCode,
        Param.ERROR_DESCRIPTION to description
    )
}