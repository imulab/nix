package io.imulab.nix.crypt.sign

import io.imulab.nix.crypt.alg.SigningAlgorithm

interface Signer {

    fun provides(): List<SigningAlgorithm>

    fun sign(doc: ByteArray, alg: SigningAlgorithm): ByteArray

    fun verify(doc: ByteArray, signature: ByteArray, alg: SigningAlgorithm): Boolean
}