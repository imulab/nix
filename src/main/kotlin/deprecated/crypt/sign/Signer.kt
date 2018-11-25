package deprecated.crypt.sign

import deprecated.crypt.alg.SigningAlgorithm

interface Signer {

    fun provides(): List<SigningAlgorithm>

    fun sign(doc: ByteArray, alg: SigningAlgorithm): ByteArray

    fun verify(doc: ByteArray, signature: ByteArray, alg: SigningAlgorithm): Boolean
}