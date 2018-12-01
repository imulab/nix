package io.imulab.nix.oauth.reserved

object ClientType {
    const val public = "public"
    const val confidential = "confidential"

    enum class Value(val spec: String) {
        Public(public), Confidential(confidential)
    }
}