package io.imulab.nix.oidc

import io.imulab.nix.oauth.OAuthAuthorizeRequest
import io.imulab.nix.oauth.OAuthRequestForm
import io.imulab.nix.oauth.OAuthSession
import io.imulab.nix.oidc.client.OidcClient
import org.jose4j.jwt.JwtClaims
import java.time.LocalDateTime

/**
 * Extension to [OAuthRequestForm] to provide access to Open ID Connect specified parameters.
 */
class OidcRequestForm(httpForm: MutableMap<String, List<String>>) : OAuthRequestForm(
    httpForm, mapOf(
        "responseMode" to OidcParam.responseMode,
        "nonce" to OidcParam.nonce,
        "display" to OidcParam.display,
        "prompt" to OidcParam.prompt,
        "maxAge" to OidcParam.maxAge,
        "uiLocales" to OidcParam.uiLocales,
        "idTokenHint" to OidcParam.idTokenHint,
        "loginHint" to OidcParam.loginHint,
        "acrValues" to OidcParam.acrValues,
        "claims" to OidcParam.claims,
        "claimsLocales" to OidcParam.claimsLocales,
        "request" to OidcParam.request,
        "requestUri" to OidcParam.requestUri,
        "registration" to OidcParam.registration,
        "iss" to OidcParam.iss,
        "targetLinkUri" to OidcParam.targetLinkUri
    )
) {
    var responseMode: String by Delegate
    var nonce: String by Delegate
    var display: String by Delegate
    var prompt: String by Delegate
    var maxAge: String by Delegate
    var uiLocales: String by Delegate
    var idTokenHint: String by Delegate
    var loginHint: String by Delegate
    var acrValues: String by Delegate
    var claims: String by Delegate
    var claimsLocales: String by Delegate
    var request: String by Delegate
    var requestUri: String by Delegate
    var registration: String by Delegate
    var iss: String by Delegate
    var targetLinkUri: String by Delegate
}

/**
 * An Open ID Connect Authorize Request.
 */
class OidcAuthorizeRequest(
    client: OidcClient,
    responseTypes: Set<String>,
    redirectUri: String,
    scopes: Set<String>,
    state: String,
    val responseMode: String?,
    val nonce: String?,
    val display: String?,
    val prompts: Set<String>,
    val maxAge: Long?,
    val uiLocales: List<String>,
    val idTokenHint: String?,
    val loginHint: String?,
    val acrValues: List<String>,
    val claims: Claims,
    val claimsLocales: List<String>,
    session: OidcSession = OidcSession()
) : OAuthAuthorizeRequest(
    client = client,
    responseTypes = responseTypes,
    redirectUri = redirectUri,
    scopes = scopes,
    state = state,
    session = session
)

/**
 * Open ID Connect User Session.
 */
class OidcSession(
    subject: String = "",
    val claims: MutableMap<String, Any> = mutableMapOf()
) : OAuthSession(subject)

/**
 * Data object of a server cached request object. This can be created when client
 * registers a set of request_uris as well as when server actively fetches content
 * from a request_uri during request.
 */
class CachedRequest(
    val requestUri: String,
    val claims: JwtClaims,
    val expiry: LocalDateTime? = null,
    val hash: String = ""
)

/**
 * Data management interface for a [CachedRequest].
 */
interface CachedRequestRepository {

    /**
     * Write a [request] to cache. Implementations may expect [CachedRequest.expiry] if
     * it is set.
     */
    suspend fun write(request: CachedRequest)

    /**
     * Find if a [CachedRequest] was cached with [requestUri].
     *
     * @param requestUri the unmodified version of the request_uri parameter, including
     * scheme, host and fragment (if any).
     */
    suspend fun find(requestUri: String): CachedRequest?
}

class CachedRequestStrategy(
    private val repository: CachedRequestRepository
)