package deprecated.client.sector.strategy

import com.google.gson.Gson
import deprecated.client.OidcClient
import deprecated.client.sector.RemoteRedirectUris
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.engine.apache.Apache
import io.ktor.client.response.readText
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import io.ktor.http.expires
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*

class FetchStrategy(private val httpClient: HttpClient = HttpClient(Apache),
                    private val json: Gson = Gson()) : SectorIdentifierStrategy {

    override suspend fun getRedirectUris(client: OidcClient): RemoteRedirectUris {
        check(client.sectorIdentifierUri.isNotEmpty())
        check(Url(client.sectorIdentifierUri).protocol == URLProtocol.HTTPS)

        return httpClient.call(client.sectorIdentifierUri).response.let { it ->
            val uris = json.fromJson(it.readText(StandardCharsets.UTF_8), ArrayList::class.java)
            if (uris.containsAll(client.redirectUris))
                TODO("redirect uris from sector_identifier_uri must contain all redirect_uris")

            val ttl: Long? = if (it.expires() == null) null else
                it.expires()!!.toInstant().epochSecond - LocalDateTime.now().toInstant(ZoneOffset.UTC).epochSecond

            RemoteRedirectUris(
                redirectUris = uris.map { u -> u.toString() }.toSet(),
                ttlSeconds = ttl
            )
        }
    }
}