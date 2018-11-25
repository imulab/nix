package deprecated.support

import org.jose4j.jwt.NumericDate
import java.time.LocalDateTime
import java.time.ZoneOffset

fun NumericDate.toLocalDateTime(): LocalDateTime {
    return LocalDateTime.ofEpochSecond(this.value, 0, ZoneOffset.UTC)
}

fun NumericDate.minusSeconds(seconds: Long): NumericDate {
    return NumericDate.fromSeconds(this.value - seconds)
}

fun NumericDate.plusSeconds(seconds: Long): NumericDate =
    NumericDate.fromSeconds(this.value + seconds)