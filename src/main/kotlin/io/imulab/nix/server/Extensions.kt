package io.imulab.nix.server

import io.ktor.config.ApplicationConfig
import io.ktor.util.KtorExperimentalAPI

@UseExperimental(KtorExperimentalAPI::class)
fun ApplicationConfig.longPropertyOrNull(path: String): Long? {
    return this.propertyOrNull(path)?.getString()?.toLongOrNull()
}

@UseExperimental(KtorExperimentalAPI::class)
fun ApplicationConfig.stringPropertyOrNull(path: String): String? {
    return this.propertyOrNull(path)?.getString()
}