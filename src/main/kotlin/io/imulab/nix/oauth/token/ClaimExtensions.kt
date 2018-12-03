package io.imulab.nix.oauth.token

import io.imulab.nix.oauth.reserved.Param
import io.imulab.nix.oauth.reserved.space
import org.jose4j.jwt.JwtClaims

fun JwtClaims.maybeString(name: String): String? =
    if (hasClaim(name))
        getStringClaimValue(name)
    else null

fun JwtClaims.maybe(name: String): Any? =
    if (hasClaim(name))
        getClaimValue(name)
    else null

fun JwtClaims.setScope(scopes: Set<String>) {
    setStringClaim(Param.scope, scopes.joinToString(separator = space))
}