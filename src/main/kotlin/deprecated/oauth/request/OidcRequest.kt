package deprecated.oauth.request

import deprecated.constant.Error
import deprecated.oauth.session.OidcSession
import deprecated.support.*
import org.jose4j.jwt.NumericDate

interface OidcRequest : OAuthRequest {

    val nonce: String
        get() = requestForm.nonce()

    val prompts: Set<Prompt>
        get() = requestForm.prompts()

    val maxAge: Long?
        get() = requestForm.maxAgeOrNull()

    val idTokenHint: String
        get() = requestForm.idTokenHint()

    val acrValues: List<String>
        get() = requestForm.acrValues()

    /**
     * Validate the state of the current request as it is.
     * Note this method does not take id_token_hint into consideration as that should be done by the
     * authentication filters.
     */
    fun ensureValidAuthenticationState() {
        val oidcSession = session.assertType<OidcSession>()
        val authTime: NumericDate? = oidcSession.idTokenClaims.maybeAuthTime()
        val reqTime: NumericDate? = oidcSession.idTokenClaims.maybeRequestAtTime()

        if (authTime != null && authTime.isOnOrAfter(NumericDate.now()))
            throw Error.Oidc.futureAuthTime()

        when {
            prompts.contains(Prompt.None) -> {
                if (prompts.size > 1)
                    throw Error.Oidc.nonePromptNotStandalone()
                if (maxAge != null) {
                    when {
                        authTime == null -> throw Error.Oidc.noAuthTime()
                        reqTime == null -> throw Error.Oidc.noRequestTime()
                        authTime.plusSeconds(maxAge!!).isBefore(reqTime) -> throw Error.Oidc.loginRequired()
                    }
                }
            }
            prompts.contains(Prompt.Login) -> {
                when {
                    authTime == null -> throw Error.Oidc.noAuthTime()
                    reqTime == null -> throw Error.Oidc.noRequestTime()
                    authTime.isBefore(reqTime) -> throw Error.Oidc.reLoginRequired()
                }
            }
        }
    }
}