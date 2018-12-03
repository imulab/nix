package io.imulab.nix.server.controller

import io.imulab.nix.server.config.NixProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono

//@RestController
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

    @GetMapping("/oauth/authorize2")
    fun authorize2(request: ServerRequest): Mono<ServerResponse> {
        println(request.attributes())
        return ServerResponse.ok().syncBody("")
    }
}