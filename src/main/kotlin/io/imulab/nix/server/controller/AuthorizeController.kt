package io.imulab.nix.server.controller

import io.imulab.nix.server.config.prop.NixProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class AuthorizeController(
    private val nixProperties: NixProperties
) {

    @GetMapping("/oauth/authorize")
    fun authorize(): String = runBlocking {
        println(Thread.currentThread().name)
        val word = withContext(Dispatchers.IO) {
            runBlocking {
                println(Thread.currentThread().name)
                "world: ${nixProperties.authorizeCode.expiration}"
            }
        }
        "hello $word"
    }
}