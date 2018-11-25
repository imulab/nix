package deprecated.oauth.response

import deprecated.constant.Param

interface AuthorizeResponse: OAuthResponse {

    var code: String

    var state: String

    var scope: String

    override fun getStatus(): Int = 200

    override fun getExtraHeaders(): Map<String, String> = emptyMap()

    override fun getParameters(): Map<String, String> = mapOf(
        Param.CODE to code,
        Param.SCOPE to scope,
        Param.STATE to state
    )
}