package deprecated.crypt.sign

import deprecated.crypt.alg.SigningAlgorithm
import org.jose4j.jca.ProviderContext
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.HmacUsingShaAlgorithm
import org.jose4j.mac.MacUtil
import java.security.Key

class HmacShaSigner private constructor(
    private val hmac: HmacUsingShaAlgorithm,
    private val key: Key,
    private val alg: SigningAlgorithm
) : Signer {

    override fun provides(): List<SigningAlgorithm> = listOf(alg)

    override fun sign(doc: ByteArray, alg: SigningAlgorithm): ByteArray {
        check(provides().contains(alg))
        return hmac.sign(key, doc, ProviderContext())
    }


    override fun verify(doc: ByteArray, signature: ByteArray, alg: SigningAlgorithm): Boolean {
        check(provides().contains(alg))
        return hmac.verifySignature(signature, key, doc, ProviderContext())
    }

    companion object {

        fun HS256(key: Key): Signer = HmacShaSigner(
            alg = SigningAlgorithm.HS256,
            key = key,
            hmac = HmacUsingShaAlgorithm(
                AlgorithmIdentifiers.HMAC_SHA256,
                MacUtil.HMAC_SHA256,
                256
            )
        )

        fun HS384(key: Key): Signer = HmacShaSigner(
            alg = SigningAlgorithm.HS384,
            key = key,
            hmac = HmacUsingShaAlgorithm(
                AlgorithmIdentifiers.HMAC_SHA384,
                MacUtil.HMAC_SHA384,
                384
            )
        )

        fun HS512(key: Key): Signer = HmacShaSigner(
            alg = SigningAlgorithm.HS512,
            key = key,
            hmac = HmacUsingShaAlgorithm(
                AlgorithmIdentifiers.HMAC_SHA512,
                MacUtil.HMAC_SHA512,
                512
            )
        )
    }
}