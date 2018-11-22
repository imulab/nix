package io.imulab.nix.constant

object ErrorCode {

    const val INVALID_REQUEST = "invalid_request"
    const val UNAUTHORIZED_CLIENT = "unauthorized_client"
    const val INVALID_REQUEST_OBJECT = "invalid_request_object"

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
    }
}