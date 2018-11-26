package io.imulab.nix.oauth

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