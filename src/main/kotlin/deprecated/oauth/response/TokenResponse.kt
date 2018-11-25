package deprecated.oauth.response

interface TokenResponse: AccessTokenAware, IdTokenAware,
    OAuthResponse {

    override fun getStatus(): Int = 200

    override fun getExtraHeaders(): Map<String, String> = emptyMap()

    override fun getParameters(): Map<String, String> {
        val m = hashMapOf<String, String>()
        m.putAll(super<AccessTokenAware>.getParameters().filter { it.value.isNotBlank() })
        m.putAll(super<IdTokenAware>.getParameters().filter { it.value.isNotBlank() })
        return m
    }
}