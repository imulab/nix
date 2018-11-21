package io.imulab.nix.constant

object ErrorCode {

    const val INVALID_REQUEST = "invalid_request"
    const val UNAUTHORIZED_CLIENT = "unauthorized_client"

    object Sub {
        const val DUPLICATE_PARAM = "duplicate_param"

        const val MISSING_CLIENT_ID = "missing_client_id"
        const val MISSING_RESPONSE_TYPE = "missing_response_type"
        const val MISSING_STATE = "missing_state"

        const val INSUFFICIENT_STATE_ENTROPY = "insufficient_state_entropy"
        const val INSUFFICIENT_NONCE_ENTROPY = "insufficient_nonce_entropy"

        const val ILLEGAL_GRANT_TYPE = "illegal_grant_type"
    }
}