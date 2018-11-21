package io.imulab.nix.crypt.hash

import io.imulab.nix.crypt.alg.HashAlgorithm
import java.security.MessageDigest

class ShaHashAlgorithmProvider private constructor(
    private val messageDigest: MessageDigest,
    private val alg: HashAlgorithm
): HashAlgorithmProvider {

    override fun supports(algorithm: HashAlgorithm): Boolean = alg == algorithm

    override fun hash(raw: ByteArray): ByteArray = messageDigest.digest(raw)

    companion object {
        fun sha256(): HashAlgorithmProvider = ShaHashAlgorithmProvider(
            messageDigest = MessageDigest.getInstance("SHA-256"),
            alg = HashAlgorithm.SHA256
        )

        fun sha384(): HashAlgorithmProvider = ShaHashAlgorithmProvider(
            messageDigest = MessageDigest.getInstance("SHA-384"),
            alg = HashAlgorithm.SHA384
        )

        fun sha512(): HashAlgorithmProvider = ShaHashAlgorithmProvider(
            messageDigest = MessageDigest.getInstance("SHA-512"),
            alg = HashAlgorithm.SHA512
        )
    }
}