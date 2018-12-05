package io.imulab.nix.oidc.jwk

import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oauth.reserved.space
import io.imulab.nix.oauth.token.maybeString
import io.imulab.nix.oidc.reserved.IdTokenClaim
import io.imulab.nix.oidc.reserved.OidcParam
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import java.time.LocalDateTime
import java.time.ZoneOffset

fun JwtClaims.responseTypes(): Set<String> =
    (maybeString(Param.responseType) ?: "")
        .split(space)
        .filter { it.isNotBlank() }
        .toSet()

fun JwtClaims.redirectUri(): String =
    maybeString(Param.redirectUri) ?: ""

fun JwtClaims.scopes(): Set<String> =
    (maybeString(Param.scope) ?: "")
        .split(space)
        .filter { it.isNotBlank() }
        .toSet()

fun JwtClaims.state(): String =
    maybeString(Param.state) ?: ""

fun JwtClaims.responseMode(): String =
    maybeString(OidcParam.responseMode) ?: ""

fun JwtClaims.nonce(): String =
    maybeString(OidcParam.nonce) ?: ""

fun JwtClaims.setNonce(nonce: String) {
    setStringClaim(OidcParam.nonce, nonce)
}

fun JwtClaims.display(): String =
    maybeString(OidcParam.display) ?: ""

fun JwtClaims.maxAge(): Long =
    maybeString(OidcParam.maxAge)?.toLongOrNull() ?: 0

fun JwtClaims.uiLocales(): List<String> =
    (maybeString(OidcParam.uiLocales) ?: "")
        .split(space)
        .filter { it.isNotBlank() }

fun JwtClaims.idTokenHint(): String =
    maybeString(OidcParam.idTokenHint) ?: ""

fun JwtClaims.loginHint(): String =
    maybeString(OidcParam.loginHint) ?: ""

fun JwtClaims.acrValues(): List<String> =
    (maybeString(OidcParam.acrValues) ?: "")
        .split(space)
        .filter { it.isNotBlank() }

fun JwtClaims.setAcr(acrValues: List<String>) {
    setStringClaim(IdTokenClaim.acr, acrValues.joinToString(separator = space))
}

//fun JwtClaims.claimsInJson(): String =
//    maybe(OidcParam.claims)
//        ?.let { GsonBuilder().serializeNulls().create().toJson(it) }
//        ?: "{}"

fun JwtClaims.claimsLocales(): List<String> =
    (maybeString(OidcParam.claimsLocales) ?: "")
        .split(space)
        .filter { it.isNotBlank() }

fun JwtClaims.authTime(): LocalDateTime? =
    if (!hasClaim(IdTokenClaim.authTime))
        null
    else
        getNumericDateClaimValue(IdTokenClaim.authTime).toLocalDateTime()

fun JwtClaims.setAuthTime(time: LocalDateTime) {
    setNumericDateClaim(IdTokenClaim.authTime, time.toNumericDate())
}

fun NumericDate.toLocalDateTime(): LocalDateTime =
    LocalDateTime.ofEpochSecond(this.value, 0, ZoneOffset.UTC)

fun LocalDateTime.toNumericDate(): NumericDate =
    NumericDate.fromSeconds(this.toEpochSecond(ZoneOffset.UTC))