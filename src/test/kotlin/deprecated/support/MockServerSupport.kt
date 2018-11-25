package deprecated.support

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import java.util.concurrent.atomic.AtomicBoolean

object MockServerSupport {

    private const val ON: Boolean = true
    private const val OFF: Boolean = false

    private lateinit var server: WireMockServer
    private val guard: AtomicBoolean = AtomicBoolean(OFF)

    fun start(): Boolean {
        if (guard.get() == ON)
            return false

        while(true) {
            if (guard.compareAndSet(OFF, ON)) {
                server = WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort())
                server.start()
                return true
            }
        }
    }

    fun url(): String = server.baseUrl()

    fun mock(rule: WireMockServer.() -> Unit) {
        server.apply(rule)
    }

    fun reset(): Boolean {
        if (guard.get() == OFF)
            return false
        server.resetAll()
        return true
    }

    fun stop() {
        if (guard.get() != OFF) {
            while (true) {
                if (guard.compareAndSet(ON, OFF)) {
                    server.stop()
                    return
                }
            }
        }
    }
}