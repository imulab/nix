package io.imulab.nix.server.authz.authn

import io.imulab.nix.oauth.AccessDenied
import io.imulab.nix.oauth.assertType
import io.imulab.nix.oidc.*
import io.imulab.nix.oidc.discovery.OidcContext
import io.imulab.nix.server.authz.LoginTokenStrategy
import io.imulab.nix.server.authz.repo.OidcAuthorizeRequestRepository
import kotlinx.coroutines.*
import java.util.*
import java.util.concurrent.ThreadLocalRandom

/**
 * Point of entry to acquire user authentication for the current request. This provider sources actual authentication
 * acquiring attempts to various [AuthenticationHandler] and only processes the logic of their result.
 *
 * When authentication has been successful, the `subject` and `auth_time` of the request session will be set. Otherwise,
 * either a login redirection or an error will result.
 */
class AuthenticationProvider(
    private val handlers: List<AuthenticationHandler>,
    private val requestRepository: OidcAuthorizeRequestRepository,
    private val loginTokenStrategy: LoginTokenStrategy,
    private val oidcContext: OidcContext
) {

    /**
     * Main logic of processing authentication.
     *
     * First, a list of [AuthenticationHandler] were tried to identity authentication from various sources. The first
     * handler that can establish authentication quits the attempting process.
     *
     * Second, determine whether the authentication state (authenticated or not) meets the `prompt` parameter, and take
     * corresponding actions. The ideal no-action-required situations are as follows:
     * - `prompt=none` is requested, and handlers had established an authentication that happened before the request.
     * - `prompt=login` is requested, and authentication had been established from the request that was identified as
     * **re-entry** (It was a continuation of the last request which resulted in login redirection).
     * - Neither `none` or `login` is requested as `prompt`, and handlers had established authentication.
     *
     * If handlers cannot establish authentication, several things could happen:
     * - If `prompt=none`, a `login_required` error is raised.
     * - If `prompt=login`, as long as the current request is not a **re-entry**, the request will be redirected to login.
     * - If neither `none` or `login` is requested as `prompt`, the request will be redirected to login.
     *
     * There are some occasions that errors might result even when authentication can be established:
     * - If `prompt=none`, but authentication time is after request time. This means a new authentication had happened
     * after client had made request. The authentication might be different with client expectation, hence the request
     * cannot continue. A access_denied error is raised.
     * - If `prompt=login` and the request is not an **re-entry**, even when authentication can be established, we need
     * to follow client direction to request a login from user. In this case, the request will be redirected to login.
     */
    suspend fun tryAuthenticate(form: OidcRequestForm, request: OidcAuthorizeRequest) {
        for (h in handlers) {
            h.attemptAuthenticate(form, request)
            if (request.isAuthenticated())
                break
        }

        with(request) {
            val oidcSession = session.assertType<OidcSession>()
            when {
                prompts.contains(Prompt.none) -> {
                    if (isAuthenticated()) {
                        checkNotNull(oidcSession.authTime) { "auth_time should have been set." }
                        check(!isReEntry()) { "redirection should not happen on none prompt" }
                        if (oidcSession.authTime!!.isAfter(requestTime))
                            throw AccessDenied.byServer("New authentication established after the request.")
                    } else {
                        throw LoginRequired.nonePrompt()
                    }
                }

                prompts.contains(Prompt.login) -> {
                    if (isAuthenticated()) {
                        if (!isReEntry())
                            prepareForRedirection(this)
                    } else {
                        if (request.isReEntry())
                            throw LoginRequired.reEntryInVain()
                        prepareForRedirection(this)
                    }
                }
                else -> {
                    if (!isAuthenticated())
                        prepareForRedirection(this)
                }
            }
            return@with
        }
    }

    private suspend fun prepareForRedirection(request: OidcAuthorizeRequest) {
        val nonce = ByteArray(oidcContext.nonceEntropy)
            .also { ThreadLocalRandom.current().nextBytes(it) }
            .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }

        withContext(Dispatchers.IO) {
            launch { requestRepository.save(request, nonce) }
        }

        val loginToken = loginTokenStrategy.generateLoginTokenRequest(request)

        throw LoginRedirectionSignal(
            loginEndpoint = "todo",
            loginToken = loginToken,
            authorizeRequestId = request.id,
            nonce = nonce
        )
    }

    private fun OidcAuthorizeRequest.isAuthenticated(): Boolean =
        session.subject.isNotEmpty() && session.assertType<OidcSession>().authTime != null

    private fun OidcAuthorizeRequest.isReEntry(): Boolean =
        session.assertType<OidcSession>().originalRequestTime != null
}