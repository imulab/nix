package io.imulab.nix.oidc.jwk

import io.imulab.nix.oidc.reserved.JwtSigningAlgorithm
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwx.JsonWebStructure
import org.jose4j.keys.resolvers.VerificationKeyResolver
import java.security.Key

class JwtVerificationKeyResolver(
    private val jwks: JsonWebKeySet,
    private val signAlg: JwtSigningAlgorithm
): VerificationKeyResolver {

    override fun resolveKey(jws: JsonWebSignature?, nestingContext: MutableList<JsonWebStructure>?): Key {
        requireNotNull(jws) {
            "Json web signature must exist."
        }

        return if (jws.keyIdHeaderValue != null)
            jwks.mustKeyWithId(jws.keyIdHeaderValue).resolvePublicKey()
        else
            jwks.mustKeyForSignature(signAlg).resolvePublicKey()
    }
}