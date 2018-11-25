package deprecated.oauth.session

import deprecated.oauth.token.TokenType
import org.jose4j.jwt.JwtClaims
import java.time.LocalDateTime

class Session(
    override val expiry: MutableMap<TokenType, LocalDateTime> = hashMapOf(),
    override var subject: String = "",
    override var username: String = "",
    override val jwtClaims: JwtClaims = JwtClaims(),
    override val jwtHeaders: MutableMap<String, String> = hashMapOf()
): OidcSession, JwtSession, OAuthSession {

    override fun clone(): OAuthSession = Session(
        expiry = HashMap(expiry),
        subject = subject,
        username = username,
        jwtClaims = JwtClaims.parse(jwtClaims.toJson()),
        jwtHeaders = HashMap(jwtHeaders)
    )
}