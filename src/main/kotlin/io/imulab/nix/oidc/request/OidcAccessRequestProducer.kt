package io.imulab.nix.oidc.request

import io.imulab.nix.oauth.client.authn.ClientAuthenticators
import io.imulab.nix.oauth.request.OAuthAccessRequest
import io.imulab.nix.oauth.request.OAuthAccessRequestProducer
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oauth.validation.SpecDefinitionValidator

class OidcAccessRequestProducer(
    grantTypeValidator: SpecDefinitionValidator,
    clientAuthenticators: ClientAuthenticators
) : OAuthAccessRequestProducer(grantTypeValidator, clientAuthenticators) {

    override suspend fun builder(form: OAuthRequestForm): OAuthAccessRequest.Builder {
        return super.builder(form).apply { session = OidcSession() }
    }
}