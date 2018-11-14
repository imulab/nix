package io.imulab.nix.astrea

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import io.imulab.astrea.spi.json.JsonEncoder
import java.nio.charset.StandardCharsets

object GsonEncoder : JsonEncoder {

    private val default: Gson = Gson()
    private val prettyJson: Gson = GsonBuilder().setPrettyPrinting().create()

    override fun encode(any: Any, pretty: Boolean): ByteArray {
        return if (pretty)
            prettyJson.toJson(any).toByteArray(StandardCharsets.UTF_8)
        else
            default.toJson(any).toByteArray(StandardCharsets.UTF_8)
    }
}