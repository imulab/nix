package deprecated.oauth.response

class NixTokenResponse(
    private val headers: MutableMap<String, String> = mutableMapOf(),
    override var accessToken: String = "",
    override var expiresIn: Long = 0,
    override var tokenType: String = "",
    override var idToken: String = ""
): TokenResponse {

    override fun getExtraHeaders(): Map<String, String> = headers
}