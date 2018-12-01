package io.imulab.nix.server.authz

import io.imulab.nix.oauth.*
import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.request.OAuthRequestForm
import io.imulab.nix.oauth.request.OAuthRequestProducer
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository

/**
 * This special implementation of [OAuthRequestProducer] resume a saved authorize request by identifying a re-entry
 * request.
 *
 * A re-entry request should carry `auth_req_id` and `nonce` parameters. When the original request is obtained
 * from repository, it will be assigned a new id and a new request time because re-entry is still a new request. However,
 * the original request time will be set in the session. All other request properties remain the same.
 *
 * If this request producer takes place, downstream producers will not get a chance to produce requests. When this
 * producer does not take place because `auth_req_id` is not provided, it will call [defaultProducer] for further
 * processing.
 */
class ResumeOidcAuthorizeRequestProducer(
    private val oidcAuthorizeRequestRepository: OidcAuthorizeRequestRepository,
    private val defaultProducer: OAuthRequestProducer
) : OAuthRequestProducer {

    override suspend fun produce(form: OAuthRequestForm): OAuthRequest {
        val f = form.assertType<OidcRequestForm>()

        if (f.authorizeRequestId.isNotEmpty()) {
            val originalRequest = oidcAuthorizeRequestRepository.get(f.authorizeRequestId, f.nonce)
                ?: throw ServerError.internal("Cannot resume authorization session.")

            return originalRequest.asBuilder().also { b ->
                b.session.originalRequestTime = originalRequest.requestTime
            }.build()
        }

        return defaultProducer.produce(f)
    }
}