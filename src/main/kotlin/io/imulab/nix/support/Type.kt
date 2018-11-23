package io.imulab.nix.support

import io.imulab.nix.oauth.session.OAuthSession

@Suppress("unchecked_cast")
inline fun <reified T : OAuthSession> OAuthSession?.assertType(): T {
    if (this == null)
        throw IllegalStateException("Session is null.")
    else if (this !is T)
        throw IllegalStateException("Session is unexpected type.")
    return this
}

fun String?.switchOnEmpty(another: String): String = if (isNullOrEmpty()) another else this!!