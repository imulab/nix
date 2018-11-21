package io.imulab.nix.support

import java.net.URI

typealias RedirectUri = String

fun RedirectUri.asValid(): RedirectUri {
    val t = checkValidity()
    if (t != null)
        throw t
    return this
}

fun RedirectUri.isValid(): Boolean = checkValidity() == null

fun RedirectUri.checkValidity(): Throwable? {
    try {
        val uri = URI(this)
        if (!uri.isAbsolute)
            return RuntimeException("TODO malformed uri")
        if (uri.rawFragment != null && uri.rawFragment.isNotBlank())
            return RuntimeException("TODO malformed uri, has fragment")
        return null
    } catch (e: Exception) {
        return e
    }
}