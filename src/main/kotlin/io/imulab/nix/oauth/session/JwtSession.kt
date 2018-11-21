package io.imulab.nix.oauth.session

import org.jose4j.jwt.JwtClaims

interface JwtSession : OAuthSession {

    val jwtClaims: JwtClaims

    val jwtHeaders: Map<String, String>
}