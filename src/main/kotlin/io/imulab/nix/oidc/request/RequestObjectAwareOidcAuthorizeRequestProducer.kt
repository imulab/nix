package io.imulab.nix.oidc.request

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oidc.claim.ClaimsJsonConverter
import io.imulab.nix.oidc.discovery.Discovery
import io.imulab.nix.oidc.jwk.*
import io.imulab.nix.oidc.reserved.OidcParam
import io.imulab.nix.oidc.reserved.StandardScope

/**
 * Functional extension to [OidcAuthorizeRequestProducer] that provides the capability to merge request objects
 * (provided as `request` parameter or `request_uri` parameter) back to the [OidcAuthorizeRequest] parsed by
 * [OidcAuthorizeRequestProducer].
 *
 * Note: as of now, the deserialization of the 'idTokenClaims' parameter take a round trip to and from JSON. This is very
 * inefficient. We intend to fix this in the future. Potentially, [ClaimsJsonConverter] will provide a capability
 * to directly parse a map.
 */
class RequestObjectAwareOidcAuthorizeRequestProducer(
    private val discovery: Discovery,
    private val firstPassProducer: OidcAuthorizeRequestProducer,
    private val requestStrategy: RequestStrategy,
    private val claimsJsonConverter: ClaimsJsonConverter
) : OAuthRequestProducer {

    override suspend fun produce(form: OAuthRequestForm): OAuthRequest {
        require(form is OidcRequestForm)

        val authorizeRequest = firstPassProducer.produce(form)
            .assertType<OidcAuthorizeRequest>()

        if (authorizeRequest.scopes.contains(StandardScope.openid)) {
            val request = requestStrategy.resolveRequest(
                request = if (discovery.requestParameterSupported) form.request else "",
                requestUri = if (discovery.requestUriParameterSupported) form.requestUri else "",
                client = authorizeRequest.client.assertType()
            )

            return authorizeRequest.asBuilder().also { b ->
                if (request.hasClaim(Param.responseType)) {
                    b.responseTypes.clear()
                    b.responseTypes.addAll(request.responseTypes())
                }
                if (request.hasClaim(Param.redirectUri))
                    b.redirectUri = request.redirectUri()
                if (request.hasClaim(Param.scope)) {
                    b.scopes.clear()
                    b.scopes.addAll(request.scopes())
                }
                if (request.hasClaim(Param.state))
                    b.state = request.state()
                if (request.hasClaim(OidcParam.responseMode))
                    b.responseMode = request.responseMode()
                if (request.hasClaim(OidcParam.nonce))
                    b.nonce = request.nonce()
                if (request.hasClaim(OidcParam.display))
                    b.display = request.display()
                if (request.hasClaim(OidcParam.maxAge))
                    b.maxAge = request.maxAge()
                if (request.hasClaim(OidcParam.uiLocales)) {
                    b.uiLocales.clear()
                    b.uiLocales.addAll(request.uiLocales())
                }
                if (request.hasClaim(OidcParam.idTokenHint))
                    b.idTokenHint = request.idTokenHint()
                if (request.hasClaim(OidcParam.loginHint))
                    b.loginHint = request.loginHint()
                if (request.hasClaim(OidcParam.acrValues)) {
                    b.acrValues.clear()
                    b.acrValues.addAll(request.acrValues())
                }
                if (request.hasClaim(OidcParam.claims)) {
                    // TODO this is very inefficient, upgrade claimsJsonConverter!!!
                    b.claims = claimsJsonConverter.fromJson(request.claimsInJson())
                }
                if (request.hasClaim(OidcParam.claimsLocales)) {
                    b.claimsLocales.clear()
                    b.claimsLocales.addAll(request.claimsLocales())
                }
                // iss and target_link_uri, if requested, still needs to be specified via parameters.
            }.build()
        }

        return authorizeRequest
    }
}