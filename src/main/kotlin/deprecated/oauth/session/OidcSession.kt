package deprecated.oauth.session

import org.jose4j.jwt.JwtClaims

interface OidcSession : JwtSession {

    val idTokenClaims: JwtClaims
        get() = this.jwtClaims

    val idTokenHeaders: Map<String, String>
        get() = this.jwtHeaders
}