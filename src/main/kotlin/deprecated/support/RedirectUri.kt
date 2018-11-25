package deprecated.support

import deprecated.constant.Error
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
            return Error.RedirectUri.invalid()
        if (uri.rawFragment != null && uri.rawFragment.isNotBlank())
            return Error.RedirectUri.invalid()
        return null
    } catch (e: Exception) {
        return Error.RedirectUri.invalid()
    }
}