package io.imulab.nix.error

import io.imulab.nix.constant.Error

class InvalidRequestException(subCode: String, message: String):
    OAuthException(code = Error.INVALID_REQUEST, subCode = subCode, description = message) {

    override fun getStatus(): Int = 401
}