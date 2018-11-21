package io.imulab.nix.oauth.token

interface EncryptedToken : Token {

    override val signature: String
        get() = ""
}