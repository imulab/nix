package io.imulab.nix.oidc.request

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oidc.claim.Claims
import io.imulab.nix.oidc.client.OidcClient

/**
 * An Open ID Connect Authorize Request.
 */
class OidcAuthorizeRequest(
    client: OidcClient,
    responseTypes: Set<String>,
    redirectUri: String,
    scopes: Set<String>,
    state: String,
    val responseMode: String,
    val nonce: String,
    val display: String,
    val prompts: Set<String>,
    val maxAge: Long,
    val uiLocales: List<String>,
    val idTokenHint: String,
    val loginHint: String,
    val acrValues: List<String>,
    val claims: Claims,
    val claimsLocales: List<String>,
    val iss: String,
    val targetLinkUri: String,
    session: OidcSession = OidcSession()
) : OAuthAuthorizeRequest(
    client = client,
    responseTypes = responseTypes,
    redirectUri = redirectUri,
    scopes = scopes,
    state = state,
    session = session
) {

    fun asBuilder(): Builder {
        return Builder().also { b ->
            b.client = client.assertType()
            b.responseTypes.addAll(responseTypes)
            b.redirectUri = redirectUri
            b.scopes.addAll(scopes)
            b.state = state
            b.responseMode = responseMode
            b.nonce = nonce
            b.display = display
            b.prompts.addAll(prompts)
            b.maxAge = maxAge
            b.uiLocales.addAll(uiLocales)
            b.idTokenHint = idTokenHint
            b.loginHint = loginHint
            b.acrValues.addAll(acrValues)
            b.claims = claims
            b.claimsLocales.addAll(claimsLocales)
            b.iss = iss
            b.targetLinkUri = targetLinkUri
            b.session = session.assertType()
        }
    }

    class Builder(
        var client: OidcClient? = null,
        var responseTypes: MutableSet<String> = mutableSetOf(),
        var redirectUri: String = "",
        var scopes: MutableSet<String> = mutableSetOf(),
        var state: String = "",
        var responseMode: String = "",
        var nonce: String = "",
        var display: String = "",
        var prompts: MutableSet<String> = mutableSetOf(),
        var maxAge: Long = 0,
        var uiLocales: MutableList<String> = mutableListOf(),
        var idTokenHint: String = "",
        var loginHint: String = "",
        var acrValues: MutableList<String> = mutableListOf(),
        var claims: Claims = Claims(),
        var claimsLocales: MutableList<String> = mutableListOf(),
        var iss: String = "",
        var targetLinkUri: String = "",
        var session: OidcSession = OidcSession()
    ) {
        fun build(): OidcAuthorizeRequest {
            checkNotNull(client)

            return OidcAuthorizeRequest(
                client = client!!,
                responseTypes = responseTypes,
                redirectUri = redirectUri,
                scopes = scopes,
                state = state,
                responseMode = responseMode,
                nonce = nonce,
                display = display,
                prompts = prompts,
                maxAge = maxAge,
                uiLocales = uiLocales,
                idTokenHint = idTokenHint,
                loginHint = loginHint,
                acrValues = acrValues,
                claims = claims,
                claimsLocales = claimsLocales,
                iss = iss,
                targetLinkUri = targetLinkUri,
                session = session
            )
        }
    }
}