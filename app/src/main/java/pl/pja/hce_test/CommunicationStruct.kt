package pl.pja.hce_test

import pl.pja.hce_test.CommunicationData.Commands
import pl.pja.hce_test.MyHostApduService.Companion.AID
import pl.pja.hce_test.MyHostApduService.Companion.MAX_DATA_PER_PACKET
import java.time.Instant
import java.util.Collections
import java.util.Date

@OptIn(ExperimentalUnsignedTypes::class)
data class CommunicationStruct(
    val command: Commands,
    val channel: UByteArray,
    var numberOfExpectedPackets: Int,
    var numberOfAcquiredPackets: Int,
    var numberOfReturnedPackets: Int,
    var numberOfSendPackets: Int,
    var data: UByteArray,
    var returnData: ArrayList<UByteArray>,
    var date: Date
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CommunicationStruct

        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        return data.contentHashCode()
    }

    fun toCommunicationData(): CommunicationData{
        return CommunicationData.getDefaultInstance().toBuilder().apply {
            command = this@CommunicationStruct.command
            addAllChannel(channel.map { it.toInt()})
            numberOfExpectedPackets = this@CommunicationStruct.numberOfExpectedPackets
            numberOfAcquiredPackets = this@CommunicationStruct.numberOfAcquiredPackets
            numberOfReturnedPackets = this@CommunicationStruct.numberOfReturnedPackets
            numberOfSendPackets = this@CommunicationStruct.numberOfSendPackets
            addAllData(data.map { it.toInt() })
            addAllReturnData(returnData.flatten().map { it.toInt() })
            date = this@CommunicationStruct.date.toInstant().toEpochMilli()
        }.build()
    }

    fun addData(data: UByteArray) {
        this.data += data
        this.numberOfAcquiredPackets += 1
        this.date = Date.from(Instant.now())
    }

    fun generateReturnData(data: UByteArray){
        returnData = data
            .chunked(MAX_DATA_PER_PACKET)
            .map { it.toUByteArray() } as ArrayList<UByteArray>
        numberOfSendPackets = returnData.size
    }

    companion object {
        fun createCommunicationStruct(communicationData: CommunicationData): CommunicationStruct{
            return CommunicationStruct(
                communicationData.command,
                communicationData.channelList.map { i -> i.toUByte() }.toUByteArray(),
                communicationData.numberOfExpectedPackets,
                communicationData.numberOfAcquiredPackets,
                communicationData.numberOfReturnedPackets,
                communicationData.numberOfSendPackets,
                communicationData.dataList.map { i -> i.toUByte() }.toUByteArray(),
                communicationData.returnDataList
                    .map { it.toUByte() }
                    .chunked(MAX_DATA_PER_PACKET)
                    .map { it.toUByteArray() } as ArrayList<UByteArray>,
                Date.from(Instant.ofEpochMilli(communicationData.date))
            )
        }

        fun createCommunicationStruct(commandApdu: UByteArray): CommunicationStruct{

            var command = Commands.values().firstOrNull {it.number == commandApdu[12 + AID.size].toInt()}
            if (command == null) command = Commands.UNRECOGNIZED

            return CommunicationStruct(
                command,
                commandApdu.copyOfRange(5 + AID.size, 9 + AID.size),
                commandApdu[10 + AID.size].toInt(),
                1,
                0,
                0,
                commandApdu.copyOfRange(13 + AID.size, commandApdu.size),
                ArrayList(),
                Date.from(Instant.now())//change to api call or switch to utc for safety
            )
        }

        fun createEmpty(): CommunicationStruct{
            return CommunicationStruct(
                Commands.UNRECOGNIZED,
                UByteArray(0),
                0,
                0,
                0,
                0,
                UByteArray(0),
                ArrayList(),
                Date.from(Instant.ofEpochMilli(0))
            )
        }
    }
}

