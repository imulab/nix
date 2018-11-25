package io.imulab.nix.oidc

import io.imulab.nix.oauth.OAuthRequestForm

/**
 * Extension to [OAuthRequestForm] to provide access to Open ID Connect specified parameters.
 */
class OidcRequestForm(httpForm: MutableMap<String, List<String>>) : OAuthRequestForm(httpForm, mapOf(
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
    "registration" to OidcParam.registration
)) {

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
}