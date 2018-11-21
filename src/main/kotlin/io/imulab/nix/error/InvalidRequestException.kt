package io.imulab.nix.error

import io.imulab.nix.constant.ErrorCode

class InvalidRequestException(subCode: String, message: String):
    OAuthException(code = ErrorCode.INVALID_REQUEST, subCode = subCode, description = message) {

    override fun getStatus(): Int = 401
}