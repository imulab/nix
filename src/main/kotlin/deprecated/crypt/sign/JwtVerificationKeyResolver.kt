package deprecated.crypt.sign

import deprecated.constant.Error
import deprecated.crypt.alg.SigningAlgorithm
import deprecated.support.findKeyForSignature
import deprecated.support.resolvePublicKey
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.Use
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwx.JsonWebStructure
import org.jose4j.keys.resolvers.VerificationKeyResolver
import java.security.Key

class JwtVerificationKeyResolver(
    private val jwks: JsonWebKeySet,
    private val mustSigningAlgorithm: SigningAlgorithm
): VerificationKeyResolver {

    override fun resolveKey(jws: JsonWebSignature?, nestingContext: MutableList<JsonWebStructure>?): Key {
        if (jws == null)
            throw Error.Jwk.notFoundForSignature()

        if (jws.algorithmHeaderValue != mustSigningAlgorithm.alg)
            throw Error.Jwk.algorithmMismatch(mustSigningAlgorithm)

        if (jws.keyIdHeaderValue != null) {
            val candidate = jwks.findJsonWebKey(jws.keyIdHeaderValue, null, Use.SIGNATURE, null)
                ?: throw Error.Jwk.notFoundForSignature()
            return candidate.resolvePublicKey()
        }

        return jwks.findKeyForSignature(mustSigningAlgorithm).resolvePublicKey()
    }
}