package io.imulab.nix.constant

import io.imulab.nix.crypt.alg.SigningAlgorithm
import io.imulab.nix.error.InvalidRequestException
import io.imulab.nix.error.InvalidRequestObjectException
import io.imulab.nix.error.OAuthException
import io.imulab.nix.oauth.request.Prompt

object Error {

    const val INVALID_REQUEST = "invalid_request"
    const val UNAUTHORIZED_CLIENT = "unauthorized_client"
    const val INVALID_REQUEST_OBJECT = "invalid_request_object"

    // TODO refactor these
    object Sub {
        const val DUPLICATE_PARAM = "duplicate_param"

        const val MISSING_CLIENT_ID = "missing_client_id"
        const val MISSING_RESPONSE_TYPE = "missing_response_type"
        const val MISSING_STATE = "missing_state"

        const val INVALID_PROMPT = "invalid_prompt"
        const val INVALID_ID_TOKEN_CLAIM = "invalid_id_token_claim"

        const val INSUFFICIENT_STATE_ENTROPY = "insufficient_state_entropy"
        const val INSUFFICIENT_NONCE_ENTROPY = "insufficient_nonce_entropy"

        const val ILLEGAL_GRANT_TYPE = "illegal_grant_type"

        const val VALUE_AND_REFERENCE = "value_and_ref"

        const val INVALID_JWKS = "invalid_jwks"
        const val JWKS_ACQUIRE_FAILURE = "jwks_acquire_failure"
        const val JWK_SEEK_FAILURE = "jwk_seek_failure"

        const val REDIRECT_URI = "redirect_uri"
    }

    object Jwk {
        private const val notFound = "jwt_not_found"
        private const val algMismatch = "alg_mismatch"

        fun notFoundForSignature() = InvalidRequestException(notFound, "Failed to locate a json web key for signature operation.")
        fun notFoundForEncryption() = InvalidRequestException(notFound, "Failed to locate a json web key for encryption operation.")
        fun algorithmMismatch(must: SigningAlgorithm) =
            InvalidRequestObjectException(algMismatch, "JWT is signed with an algorithm different than a registered one. Expects: ${must.alg}")
        fun noneAlgorithmAtAuthorizeEndpoint() =
            InvalidRequestException(algMismatch, "It is illegal to use <none> algorithm to sign id_token to be returned at authorization endpoint.")
    }

    object Jwks {
        private const val noResolve = "no_jwks"
        private const val invalid = "invalid_jwks"

        fun invalid() = InvalidRequestException(invalid, "Json web key set is invalid.")
        fun noJwks() = InvalidRequestException(noResolve, "Failed to resolve a json web key set for further operation.")
    }

    object Enum {
        private const val invalid = "invalid"

        fun invalid(name: String? = null): OAuthException = InvalidRequestException(
            subCode = invalid + "_${name ?: "value"}",
            message = "Parameter <${name ?: "?"}> has invalid value."
        )
    }

    object State {
        private const val missing = "missing_state"
        private const val entropy = "insufficient_entropy"

        fun missing(): OAuthException = InvalidRequestException(missing, "${Param.STATE} is missing.")
        fun entropy(): OAuthException = InvalidRequestException(entropy, "${Param.STATE} does not have sufficient entropy.")
    }

    object RedirectUri {
        private const val none = "no_redirect_uri"
        private const val multiple = "multiple_redirect_uri"
        private const val rouge = "rouge_redirect_uri"
        private const val invalid = "invalid_redirect_uri"

        fun noneRegistered(): OAuthException = InvalidRequestException(none,
            "Cannot select ${Param.REDIRECT_URI}: none was registered.")
        fun multipleRegistered(): OAuthException = InvalidRequestException(multiple,
            "Cannot select ${Param.REDIRECT_URI}: multiple registered.")
        fun rouge(): OAuthException = InvalidRequestException(rouge,
            "Cannot select ${Param.REDIRECT_URI}: provided value not registered.")
        fun invalid(): OAuthException = InvalidRequestException(invalid,
            "${Param.REDIRECT_URI} is invalid: must be absolute url with no fragment and https protocol (except from localhost).")
    }

    object Oidc {
        private const val futureAuthTime = "future_auth_time"
        private const val noAuthTime = "missing_auth_time"
        private const val noReqTime = "missing_req_time"
        private const val authExpired = "expired_auth"
        private const val invalidPrompt = "invalid_prompt"

        fun futureAuthTime() = InvalidRequestException(futureAuthTime, "Authentication time cannot be in the future.")
        fun noAuthTime() = InvalidRequestException(noAuthTime, "Missing authentication time. Authentication time must be present when max age is present.")
        fun noRequestTime() = InvalidRequestException(noReqTime, "Missing request time. Request time must be present when max age is present.")
        fun nonePromptNotStandalone() = InvalidRequestException(invalidPrompt, "Prompt <${Prompt.None.specValue}> cannot be accompanied by other prompts.")

        fun loginRequired() = InvalidRequestException(authExpired, "TODO change this to login_required")    // TODO
        fun reLoginRequired() = InvalidRequestException(authExpired, "TODO change this to login_required")    // TODO
    }

    object RequestObject {
        private const val acquire = "acquire_failure"

        fun acquireFailed() = InvalidRequestObjectException(acquire, "Failed to acquire request object.")
    }
}