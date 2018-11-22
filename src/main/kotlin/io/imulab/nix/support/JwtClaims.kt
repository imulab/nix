package io.imulab.nix.support

import io.imulab.nix.constant.Param
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate

fun JwtClaims.optionalStringClaim(name: String, default: String = ""): String {
    return if (this.hasClaim(name))
        this.getStringClaimValue(name)
    else default
}

fun JwtClaims.setAccessTokenHash(hash: String) {
    this.setStringClaim(Param.ACCESS_TOKEN_HASH, hash)
}

fun JwtClaims.getAccessTokenHash(): String {
    return this.optionalStringClaim(Param.ACCESS_TOKEN_HASH)
}

fun JwtClaims.setAcr(value: String) {
    this.setStringClaim(Param.ACR, value)
}

fun JwtClaims.getAcr(): String {
    return this.optionalStringClaim(Param.ACR)
}

fun JwtClaims.setCodeHash(hash: String) {
    this.setStringClaim(Param.CODE_HASH, hash)
}

fun JwtClaims.getCodeHash(): String {
    return this.optionalStringClaim(Param.CODE_HASH)
}

fun JwtClaims.setAuthTime(time: NumericDate) {
    this.setNumericDateClaim(Param.AUTH_TIME, time)
}

fun JwtClaims.getAuthTime(): NumericDate? {
    return this.getNumericDateClaimValue(Param.AUTH_TIME)
}

fun JwtClaims.getRequestAtTime(): NumericDate? {
    return this.getNumericDateClaimValue(Param.REQUEST_AT_TIME)
}

fun JwtClaims.setRequestAtTime(time: NumericDate) {
    this.setNumericDateClaim(Param.REQUEST_AT_TIME, time)
}

fun JwtClaims.setNonce(nonce: String) {
    this.setStringClaim(Param.NONCE, nonce)
}

fun JwtClaims.setScopes(scopes: List<String>) {
    this.setStringListClaim(Param.NONCE, scopes)
}

fun JwtClaims.getScopes(): List<String> {
    return if (this.hasClaim(Param.SCOPE))
        this.getStringListClaimValue(Param.SCOPE)
    else emptyList()
}