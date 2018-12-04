package io.imulab.nix.oauth

import io.imulab.nix.oauth.error.InvalidRequest
import io.imulab.nix.oauth.error.InvalidScope

/**
 * Extension on Map to ensure a key has only one value (single element list).
 */
fun Map<String, List<String>>.singleOrNull(key: String): String? {
    val v = this[key]
    return when {
        v == null -> null
        v.size > 1 -> throw InvalidRequest.duplicate(key)
        else -> return v[0]
    }
}

fun MutableMap<String, String>.putIfNotEmpty(key: String, value: String) {
    if (value.isNotEmpty())
        put(key, value)
}

fun String.mustNotMalformedScope(): String {
    val chars = this.toCharArray().toSortedSet()
    return when {
        chars.first() < '!' -> throw InvalidScope.malformed(this)
        chars.last() > '~' -> throw InvalidScope.malformed(this)
        chars.contains('"') -> throw InvalidScope.malformed(this)
        chars.contains('\\') -> throw InvalidScope.malformed(this)
        else -> this
    }
}

fun String?.ifNotNullOrEmpty(action: (String) -> Unit) {
    this.let {
        if (!it.isNullOrEmpty())
            action(it)
    }
}

fun Set<String>.exactly(value: String): Boolean = size == 1 && contains(value)

@Suppress("unchecked_cast")
inline fun <reified T : Any> Any?.assertType(): T {
    if (this == null)
        throw NullPointerException("Cannot assert type: it is null.")
    else if (this !is T)
        throw IllegalStateException("Failed assert: unexpected type")
    return this
}