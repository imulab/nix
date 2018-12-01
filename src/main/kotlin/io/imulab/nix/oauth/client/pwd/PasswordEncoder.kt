package io.imulab.nix.oauth.client.pwd

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