package io.imulab.nix.oidc.request

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.client.ClientLookup
import io.imulab.nix.oauth.request.OAuthAuthorizeRequest
import io.imulab.nix.oauth.request.OAuthAuthorizeRequestProducer
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oauth.reserved.space
import io.imulab.nix.oauth.validation.SpecDefinitionValidator
import io.imulab.nix.oidc.ClaimsJsonConverter

/**
 * Implementation of [OAuthRequestProducer] to produce a [OidcAuthorizeRequest]. This class utilizes
 * [OAuthAuthorizeRequestProducer] to do the basis work and transform built value back to
 * [OidcAuthorizeRequest.Builder].
 */
class OidcAuthorizeRequestProducer(
    lookup: ClientLookup,
    responseTypeValidator: SpecDefinitionValidator,
    private val claimsJsonConverter: ClaimsJsonConverter
) : OAuthAuthorizeRequestProducer(lookup, responseTypeValidator) {

    override suspend fun produce(form: OAuthRequestForm): OAuthRequest {
        require(form is OidcRequestForm) { "this producer only produces from OidcRequestForm" }
        val oauthRequest = super.produce(form).assertType<OAuthAuthorizeRequest>()

        return OidcAuthorizeRequest.Builder().also { b ->
            oauthRequest.run {
                b.client = client.assertType()
                b.responseTypes.addAll(responseTypes)
                b.redirectUri = redirectUri
                b.scopes.addAll(scopes)
                b.state = state
            }

            form.run {
                b.responseMode = responseMode
                b.nonce = nonce
                b.display = display
                b.prompts.addAll(prompt.split(space).filter { it.isNotBlank() })
                b.maxAge = maxAge.toLongOrNull() ?: 0
                b.uiLocales.addAll(uiLocales.split(space).filter { it.isNotBlank() })
                b.idTokenHint = idTokenHint
                b.loginHint = loginHint
                b.acrValues.addAll(acrValues.split(space).filter { it.isNotBlank() })
                b.claims = claimsJsonConverter.fromJson(claims)
                b.claimsLocales.addAll(claimsLocales.split(space).filter { it.isNotBlank() })
                b.iss = iss
                b.targetLinkUri = targetLinkUri
                b.session = OidcSession()
            }
        }.build()
    }
}