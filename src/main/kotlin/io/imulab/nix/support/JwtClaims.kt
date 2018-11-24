package io.imulab.nix.support

import io.imulab.nix.constant.Param
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate

fun JwtClaims.maybe(name: String, default: String = ""): String {
    return if (this.hasClaim(name))
        this.getStringClaimValue(name)
    else default
}

fun JwtClaims.setAccessTokenHash(hash: String) {
    this.setStringClaim(Param.ACCESS_TOKEN_HASH, hash)
}

fun JwtClaims.maybeAccessTokenHash(): String {
    return this.maybe(Param.ACCESS_TOKEN_HASH)
}

fun JwtClaims.setAcr(value: String) {
    this.setStringClaim(Param.ACR, value)
}

fun JwtClaims.maybeAcr(): String {
    return this.maybe(Param.ACR)
}

fun JwtClaims.maybeAmr(): String = this.maybe(Param.AMR)

fun JwtClaims.setAmr(v: String) {
    this.setStringClaim(Param.AMR, v)
}

fun JwtClaims.setAzp(v: String) {
    this.setStringClaim(Param.AZP, v)
}

fun JwtClaims.maybeAzp(): String = this.maybe(Param.AZP)

fun JwtClaims.setCodeHash(hash: String) {
    this.setStringClaim(Param.CODE_HASH, hash)
}

fun JwtClaims.maybeCodeHash(): String {
    return this.maybe(Param.CODE_HASH)
}

fun JwtClaims.setAuthTime(time: NumericDate) {
    this.setNumericDateClaim(Param.AUTH_TIME, time)
}

fun JwtClaims.maybeAuthTime(): NumericDate? {
    return this.getNumericDateClaimValue(Param.AUTH_TIME)
}

fun JwtClaims.maybeRequestAtTime(): NumericDate? {
    return this.getNumericDateClaimValue(Param.REQUEST_AT_TIME)
}

fun JwtClaims.setRequestAtTime(time: NumericDate) {
    this.setNumericDateClaim(Param.REQUEST_AT_TIME, time)
}

fun JwtClaims.setNonce(nonce: String) {
    this.setStringClaim(Param.NONCE, nonce)
}

fun JwtClaims.maybeNonce(): String = this.maybe(Param.NONCE)

fun JwtClaims.maybeState(): String = this.maybe(Param.STATE)

fun JwtClaims.maybeRedirectUri(): String = this.maybe(Param.REDIRECT_URI)

fun JwtClaims.maybeResponseMode(): String = this.maybe(Param.RESPONSE_MODE)

fun JwtClaims.setScopes(scopes: List<String>) {
    this.setStringListClaim(Param.SCOPE, scopes)
}

fun JwtClaims.getScopes(): List<String> {
    return if (this.hasClaim(Param.SCOPE))
        this.getStringListClaimValue(Param.SCOPE)
    else emptyList()
}