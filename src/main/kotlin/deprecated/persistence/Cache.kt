package deprecated.persistence

import java.time.LocalDateTime

interface Cache<ID, T> {

    /**
     * Read item from cache.
     */
    suspend fun read(id: ID): T?

    /**
     * Write item to a cache
     */
    suspend fun write(id: ID, value: T, expiry: LocalDateTime? = null)
}