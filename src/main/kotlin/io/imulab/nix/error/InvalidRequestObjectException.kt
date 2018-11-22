package io.imulab.nix.error

import io.imulab.nix.constant.ErrorCode

class InvalidRequestObjectException(message: String):
    OAuthException(ErrorCode.INVALID_REQUEST_OBJECT, "", message) {
    override fun getStatus(): Int = 400
}