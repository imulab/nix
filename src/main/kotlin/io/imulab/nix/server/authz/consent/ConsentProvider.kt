package io.imulab.nix.server.authz.consent

import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.oidc.error.InteractionRequired
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcRequestForm
import io.imulab.nix.oidc.reserved.Prompt
import io.imulab.nix.server.authz.authn.AuthenticationProvider
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.*
import java.util.concurrent.ThreadLocalRandom

/**
 * Point of entry to acquire user consent for the current request. This provider sources actual authorization
 * acquiring attempts to various [ConsentHandler] and only processes the logic of their result.
 *
 * When authorization has been successful, the grant scopes and optionally claims of the request will be set. Otherwise,
 * either a consent redirection or an error will result.
 */
class ConsentProvider(
    private val handlers: List<ConsentHandler>,
    private val consentTokenStrategy: ConsentTokenStrategy,
    private val requestRepository: OidcAuthorizeRequestRepository,
    private val requireAuthentication: Boolean = true,
    private val oidcContext: OidcContext,
    private val consentProviderEndpoint: String
) {

    /**
     * Main logic of processing user consent
     *
     * First, provider checks if authentication status is required and if user has authentication status. This allows
     * combining uses of both [AuthenticationProvider] and [ConsentProvider] in the case that server can gather both
     * `login_token` and `consent_token` and send them to the same provider for both authentication and consent.
     *
     * First, a list of [ConsentProvider] were tried to obtain consent from various sources. The first
     * handler that can establish consent information quits the attempting process.
     *
     * Second, determine whether the consent state meets the `prompt` parameter, and take corresponding actions.
     * - If `prompt=none`, a `interaction_required` error is raised.
     * - If `prompt=consent`, a consent redirection is requested no matter the consent state.
     * - If neither `none` or `consent` is specified in `prompt`, a consent redirection is request only when no scope
     * was granted.
     */
    suspend fun tryAuthorize(form: OidcRequestForm, request: OidcAuthorizeRequest, rawCall: Any) {
        request.checkAuthentication()

        for (h in handlers) {
            h.attemptAuthorize(form, request, rawCall)
            if (request.hasAuthorization())
                break
        }

        with(request) {
            when {
                prompts.contains(Prompt.none) -> {
                    if (!request.hasAuthorization())
                        throw InteractionRequired.nonePrompt()
                }
                prompts.contains(Prompt.consent) -> {
                    prepareForRedirection(request)
                }
                else -> {
                    if (!hasAuthorization())
                        prepareForRedirection(this)
                }
            }
        }
    }

    private fun OidcAuthorizeRequest.checkAuthentication() {
        if (requireAuthentication && session.subject.isEmpty())
            throw IllegalStateException("Authentication is required for consent provider to work.")
    }

    /**
     * Utility method to detect if the request has (some) authorization. A request that has authorization is one
     * that will be allowed to proceed (will not raise access_denied error). A request has authorization when
     * its granted scopes are not empty or it does not require scopes to be granted in the first place.
     */
    private fun OidcAuthorizeRequest.hasAuthorization(): Boolean =
            this.scopes.isEmpty() || this.grantedScopes.isNotEmpty()

    private suspend fun prepareForRedirection(request: OidcAuthorizeRequest) {
        val nonce = ByteArray(oidcContext.nonceEntropy)
            .also { ThreadLocalRandom.current().nextBytes(it) }
            .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }

        withContext(Dispatchers.IO) {
            launch { requestRepository.save(request, nonce) }
        }

        val consentToken = consentTokenStrategy.generateConsentTokenRequest(request)

        throw ConsentRedirectionSignal(
            consentEndpoint = consentProviderEndpoint,
            callbackUri = oidcContext.authorizeEndpointUrl,
            consentToken = consentToken,
            authorizeRequestId = request.id,
            nonce = nonce
        )
    }
}