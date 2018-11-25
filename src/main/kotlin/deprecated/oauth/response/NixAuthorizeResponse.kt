package deprecated.oauth.response

class NixAuthorizeResponse(
    override var code: String = "",
    override var state: String = "",
    override var scope: String = "",
    override var accessToken: String = "",
    override var expiresIn: Long = 0,
    override var tokenType: String = "",
    override var idToken: String = ""
): AuthorizeResponse, AccessTokenAware,
    IdTokenAware {

    override fun getStatus(): Int = 200

    override fun getExtraHeaders(): Map<String, String> = emptyMap()

    override fun getParameters(): Map<String, String> {
        val m = hashMapOf<String, String>()
        m.putAll(super<AuthorizeResponse>.getParameters().filter { it.value.isNotBlank() })
        m.putAll(super<AccessTokenAware>.getParameters().filter { it.value.isNotBlank() })
        m.putAll(super<IdTokenAware>.getParameters().filter { it.value.isNotBlank() })
        return m
    }
}