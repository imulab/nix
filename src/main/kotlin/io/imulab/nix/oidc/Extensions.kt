package io.imulab.nix.oidc

import com.google.gson.GsonBuilder
import io.imulab.nix.oauth.Param
import io.imulab.nix.oauth.space
import org.jose4j.jwt.JwtClaims

fun JwtClaims.maybeString(name: String): String? =
    if (hasClaim(name))
        getStringClaimValue(name)
    else null

fun JwtClaims.maybe(name: String): Any? =
    if (hasClaim(name))
        getClaimValue(name)
    else null

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

fun JwtClaims.display(): String =
    maybeString(OidcParam.display) ?: ""

fun JwtClaims.maxAge(): Long =
    maybe(OidcParam.maxAge) as? Long ?: 0

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

fun JwtClaims.claimsInJson(): String =
    maybe(OidcParam.claims)
        ?.let { GsonBuilder().serializeNulls().create().toJson(it) }
        ?: "{}"

fun JwtClaims.claimsLocales(): List<String> =
    (maybeString(OidcParam.claimsLocales) ?: "")
        .split(space)
        .filter { it.isNotBlank() }