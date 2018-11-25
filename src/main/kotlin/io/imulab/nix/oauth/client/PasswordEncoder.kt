package io.imulab.nix.oauth.client

import org.mindrot.jbcrypt.BCrypt

/**
 * Provides functions to encode a plain text password and compare one with its
 * encoded form.
 */
interface PasswordEncoder {

    /**
     * Encodes the [plain] password.
     */
    fun encode(plain: String): String

    /**
     * Returns true if the [raw] password is indeed the plain text form of [encoded] password.
     * Otherwise, returns false.
     */
    fun matches(raw: String, encoded: String): Boolean
}

/**
 * Implementation of [PasswordEncoder] that uses bcrypt algorithm for encoding.
 */
class BCryptPasswordEncoder(private val complexity: Int = 10) : PasswordEncoder {

    override fun encode(plain: String): String {
        return BCrypt.hashpw(plain, BCrypt.gensalt(complexity))
    }

    override fun matches(raw: String, encoded: String): Boolean {
        return BCrypt.checkpw(raw, encoded)
    }
}