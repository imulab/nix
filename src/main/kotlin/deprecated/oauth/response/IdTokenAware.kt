package deprecated.oauth.response

import deprecated.constant.Param

interface IdTokenAware : OAuthResponse {

    var idToken: String

    override fun getStatus(): Int = 200

    override fun getExtraHeaders(): Map<String, String> = emptyMap()

    override fun getParameters(): Map<String, String> = mapOf(
        Param.ID_TOKEN to idToken
    )
}