package pl.pja.hce_test

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.Serializer
import com.google.protobuf.InvalidProtocolBufferException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream

object CommunicationDataSerializer : Serializer<CommunicationData> {
    override val defaultValue: CommunicationData = CommunicationData.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): CommunicationData {
        try {
            return CommunicationData.parseFrom(input)
        } catch (exception: InvalidProtocolBufferException) {
            throw CorruptionException("Cannot read proto.", exception)
        }
    }

    override suspend fun writeTo(t: CommunicationData, output: OutputStream) {
        t.writeTo(output)
    }
}