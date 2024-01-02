package pl.pja.hce_test

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.Serializer
import com.google.protobuf.InvalidProtocolBufferException
import java.io.InputStream
import java.io.OutputStream

object KeyAliasesSerializer : Serializer<KeyAliases> {
    override val defaultValue: KeyAliases = KeyAliases.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): KeyAliases {
        try {
            return KeyAliases.parseFrom(input)
        } catch (exception: InvalidProtocolBufferException) {
            throw CorruptionException("Cannot read proto.", exception)
        }
    }

    override suspend fun writeTo(t: KeyAliases, output: OutputStream) {
        t.writeTo(output)
    }
}
