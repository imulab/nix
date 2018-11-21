package io.imulab.nix.crypt.hash

import io.imulab.nix.crypt.alg.HashAlgorithm

/**
 * Algorithm for hashing bytes.
 */
interface HashAlgorithmProvider {

    /**
     * Returns true if the implementation supports the [algorithm].
     */
    fun supports(algorithm: HashAlgorithm): Boolean

    /**
     * Hash the [raw] bytes and returns the hashed bytes.
     */
    fun hash(raw: ByteArray): ByteArray
}