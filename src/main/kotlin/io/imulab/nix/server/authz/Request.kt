package io.imulab.nix.server.authz

import io.imulab.nix.oauth.OAuthRequest
import io.imulab.nix.oauth.OAuthRequestForm
import io.imulab.nix.oauth.OAuthRequestProducer
import io.imulab.nix.oidc.OidcAuthorizeRequestProducer

/**
 * Master authorize request producer to dispatch producing job to respective producers. When the form contains
 * a `login_token` parameter, we assume this is an authentication re-entry, hence delegates the job to
 * [LoginTokenAwareOidcRequestStrategy]. When the form contains a `consent_token` parameter, we assume this is
 * a consent re-entry, hence delegates the job to [ConsentTokenAwareOidcRequestStrategy]. If none of these tokens
 * are present, we assume this is a first-time entry, hence delegating the job to [OidcAuthorizeRequestProducer].
 */
class MasterAuthorizeRequestProducer(
    private val loginTokenAwareProducer: LoginTokenAwareOidcRequestStrategy,
    private val consentTokenAwareProducer: ConsentTokenAwareOidcRequestStrategy,
    private val oidcAuthorizeRequestProducer: OidcAuthorizeRequestProducer
): OAuthRequestProducer {

    override suspend fun produce(form: OAuthRequestForm): OAuthRequest {
        return when {
            form.loginToken.isNotEmpty() -> loginTokenAwareProducer.produce(form)
            form.consentToken.isNotEmpty() -> consentTokenAwareProducer.produce(form)
            else -> oidcAuthorizeRequestProducer.produce(form)
        }
    }
}