package io.imulab.nix.oidc.request

import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oidc.reserved.LoginTokenParam
import io.imulab.nix.oidc.reserved.OidcParam

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
        "targetLinkUri" to OidcParam.targetLinkUri,
        "clientAssertion" to OidcParam.clientAssertion,
        "clientAssertionType" to OidcParam.clientAssertionType,
        "authorizeRequestId" to LoginTokenParam.authorizeRequestId
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
    var clientAssertion: String by Delegate
    var clientAssertionType: String by Delegate
    var authorizeRequestId: String by Delegate
}