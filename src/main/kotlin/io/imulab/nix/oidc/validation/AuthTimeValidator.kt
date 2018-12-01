package io.imulab.nix.oidc.validation

import io.imulab.nix.oauth.assertType
import io.imulab.nix.oauth.error.AccessDenied
import io.imulab.nix.oauth.error.ServerError
import io.imulab.nix.oauth.request.OAuthRequest
import io.imulab.nix.oauth.validation.OAuthRequestValidation
import io.imulab.nix.oidc.request.OidcAuthorizeRequest
import io.imulab.nix.oidc.request.OidcSession
import io.imulab.nix.oidc.reserved.IdTokenClaim
import io.imulab.nix.oidc.reserved.Prompt
import java.time.LocalDateTime

/**
 * Validates the relation between `max_age`, `auth_time` and `prompt`. This validator assumes all previous
 * authorization request has been revived and authentication information has also been merged into request
 * session. Hence, it is recommended to place this validator behind the aforementioned actions.
 *
 * Under these assumptions, this validator enforces the following rules:
 * - `auth_time` is optional when `max_age` is not specified, or it has not been requested as an essential claim.
 * - `auth_time`, if present, must not be in the future
 * - `auth_time` and `max_age`, if present, must form such relation that `auth_time + max_age >= now`.
 * - when `prompt` is set to `login`, `auth_time` must happen after the original (before redirection) request time.
 * - when `prompt` is set to `none`, `auth_time` must happen before the current request time.
 */
object AuthTimeValidator : OAuthRequestValidation {
    override fun validate(request: OAuthRequest) {
        val ar = request.assertType<OidcAuthorizeRequest>()
        val session = ar.session.assertType<OidcSession>()
        val authTime = session.authTime

        if (authTime == null) {
            when {
                ar.maxAge > 0 ->
                    throw ServerError.internal("<auth_time> must be specified when <max_age> is specified.")
                ar.claims.hasEssentialClaim(IdTokenClaim.authTime) ->
                    throw ServerError.internal("<auth_time> must be specified when it is requested as an essential claim.")
            }
            return
        }

        if (authTime.isAfter(LocalDateTime.now()))
            throw AccessDenied.byServer("Untrusted authentication (happened in the future).")

        if (ar.maxAge > 0) {
            if (authTime.plusSeconds(ar.maxAge).isBefore(LocalDateTime.now()))
                throw AccessDenied.authenticationExpired()
        }

        if (ar.prompts.contains(Prompt.login)) {
            if (authTime.isBefore(session.originalRequestTime ?: ar.requestTime))
                throw AccessDenied.oldAuthenticationOnLoginPrompt()
        }

        if (ar.prompts.contains(Prompt.none)) {
            if (authTime.isAfter(ar.requestTime))
                throw AccessDenied.newAuthenticationOnNonePrompt()
        }
    }
}