package io.imulab.nix.error

import io.imulab.nix.constant.Error

class InvalidRequestObjectException(subCode: String, message: String):
    OAuthException(Error.INVALID_REQUEST_OBJECT, subCode, message) {
    override fun getStatus(): Int = 400
}