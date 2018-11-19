package io.imulab.nix.support

import org.kodein.di.Kodein
import org.kodein.di.conf.global

/**
 * Auto clears Kodein DI global context after each.
 */
inline fun <reified T: Any> List<T>.forEachAutoClear(f: (T) -> Unit) = this.forEach { e ->
    f(e)
    Kodein.global.clear()
}