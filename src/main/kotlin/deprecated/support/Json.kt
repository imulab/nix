package deprecated.support

import com.google.gson.ExclusionStrategy
import com.google.gson.FieldAttributes

object JsonExclusionStrategy: ExclusionStrategy {

    override fun shouldSkipClass(clazz: Class<*>?): Boolean =
        clazz?.getAnnotation(JsonSkip::class.java) != null

    override fun shouldSkipField(f: FieldAttributes?): Boolean =
        f?.getAnnotation(JsonSkip::class.java) != null
}

@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
@Retention(AnnotationRetention.RUNTIME)
annotation class JsonSkip