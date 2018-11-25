package deprecated.oauth.token.strategy

import deprecated.constant.Error
import deprecated.constant.Misc
import deprecated.crypt.alg.SigningAlgorithm
import deprecated.oauth.request.OAuthRequest
import deprecated.oauth.token.SignedToken
import deprecated.oauth.token.Token
import deprecated.oauth.token.TokenType
import org.jose4j.jca.ProviderContext
import org.jose4j.jws.HmacUsingShaAlgorithm
import java.security.Key
import java.util.*
import java.util.concurrent.ThreadLocalRandom

interface AuthorizeCodeStrategy {

    fun fromRaw(raw: String): Token

    fun generateCode(request: OAuthRequest): Token

    fun verifyCode(request: OAuthRequest, code: String): Token
}

abstract class HmacBaseStrategy(
    protected val key: Key,
    signingAlgorithm: SigningAlgorithm,
    private val codeLength: Int = 16
) {
    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder: Base64.Decoder = Base64.getUrlDecoder()
    protected val algorithm: HmacUsingShaAlgorithm = when (signingAlgorithm) {
        SigningAlgorithm.HS256 ->
            HmacUsingShaAlgorithm.HmacSha256()
        SigningAlgorithm.HS384 ->
            HmacUsingShaAlgorithm.HmacSha384()
        SigningAlgorithm.HS512 ->
            HmacUsingShaAlgorithm.HmacSha512()
        else -> throw IllegalStateException("This strategy can only work with HMAC-SHA2 series algorithms.")
    }

    abstract fun createToken(value: String, signature: String): Token

    abstract fun badSignatureException(): Throwable

    abstract fun badFormatException(): Throwable

    protected fun createFromRaw(raw: String): Token {
        val parts = requireTwoParts(raw)
        return createToken(value = parts[0] + Misc.DOT + parts[1], signature = parts[1])
    }

    protected fun generate(): Token {
        val randomBytes = ByteArray(codeLength).also {
            ThreadLocalRandom.current().nextBytes(it)
        }
        val signatureBytes = algorithm.sign(key, randomBytes, ProviderContext())
        return createFromRaw(encoder.encodeToString(randomBytes) + Misc.DOT + encoder.encodeToString(signatureBytes))
    }

    protected fun verify(token: Token): Token {
        val parts = requireTwoParts(token.value)
        if (!algorithm.verifySignature(
                decoder.decode(parts[1]),
                key,
                decoder.decode(parts[0]),
                ProviderContext()
            )
        ) {
            throw badSignatureException()
        }
        return createFromRaw(parts[0] + Misc.DOT + parts[1])
    }

    private fun requireTwoParts(raw: String): List<String> {
        val parts = raw.split(Misc.DOT)
        if (parts.size != 2)
            throw badFormatException()
        return parts
    }
}

class HmacAuthorizeCodeStrategy(key: Key, signingAlgorithm: SigningAlgorithm, codeLength: Int = 16) :
    HmacBaseStrategy(key, signingAlgorithm, codeLength),
    AuthorizeCodeStrategy {

    override fun createToken(value: String, signature: String): Token =
        SignedToken(TokenType.AuthorizeCode, value, signature)

    override fun badSignatureException(): Throwable = Error.AuthorizeCode.badSignature()

    override fun badFormatException(): Throwable = Error.AuthorizeCode.badFormat()

    override fun fromRaw(raw: String): Token = createFromRaw(raw)

    override fun generateCode(request: OAuthRequest): Token = generate()

    override fun verifyCode(request: OAuthRequest, code: String): Token = verify(fromRaw(code))
}