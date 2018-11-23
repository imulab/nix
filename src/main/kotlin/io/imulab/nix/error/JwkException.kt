package io.imulab.nix.error

import io.imulab.nix.constant.Error
import io.imulab.nix.constant.Error.INVALID_REQUEST

open class JwkException(subCode: String, message: String) : OAuthException(
    code = INVALID_REQUEST,
    subCode = subCode,
    description = message
) {
    override fun getStatus(): Int = 400

    companion object {

        class JwkSeekException: JwkException(
            subCode = Error.Sub.JWK_SEEK_FAILURE,
            message = "Cannot locate any Json Web Key for operation.")

        class JwksAcquireException(message: String? = null):
            JwkException(
                subCode = Error.Sub.JWKS_ACQUIRE_FAILURE,
                message = message ?: "Failed to acquire Json Web Key Set.")
    }
}