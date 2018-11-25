package deprecated.support

import io.ktor.http.Url
import io.ktor.http.decodeURLQueryComponent
import org.kodein.di.Kodein
import org.kodein.di.conf.global

/**
 * Auto clears Kodein DI global context after each.
 */
inline fun <reified T: Any> List<T>.forEachAutoClear(f: (T) -> Unit) = this.forEach { e ->
    f(e)
    Kodein.global.clear()
}

fun Url.decodedFragmentsAsMap(): Map<String, String> =
    this.fragment.decodeURLQueryComponent()
        .split("&")
        .map { it.split("=").let { p -> Pair(p[0], p[1]) } }
        .toMap()