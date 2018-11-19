package io.imulab.nix.config

import io.ktor.application.Application
import io.ktor.util.KtorExperimentalAPI

@UseExperimental(KtorExperimentalAPI::class)
fun Application.stringConfig(key: String, default: String = "") =
    environment.config.propertyOrNull(key)?.getString() ?: default

fun Application.booleanConfig(key: String, default: Boolean = false) =
    stringConfig(key, default.toString()).toBoolean()