package pl.pja.hce_test

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.Serializer
import com.google.protobuf.InvalidProtocolBufferException
import java.io.InputStream
import java.io.OutputStream

object SavedKeysSerializer : Serializer<SavedKeys> {
    override val defaultValue: SavedKeys = SavedKeys.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): SavedKeys {
        try {
            return SavedKeys.parseFrom(input)
        } catch (exception: InvalidProtocolBufferException) {
            throw CorruptionException("Cannot read proto.", exception)
        }
    }

    override suspend fun writeTo(t: SavedKeys, output: OutputStream) {
        t.writeTo(output)
    }
}
