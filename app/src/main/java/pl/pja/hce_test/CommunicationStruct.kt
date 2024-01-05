package pl.pja.hce_test

import pl.pja.hce_test.CommunicationData.Commands
import pl.pja.hce_test.U2FHostApduService.Companion.AID
import pl.pja.hce_test.U2FHostApduService.Companion.MAX_DATA_PER_PACKET
import java.time.Instant
import java.util.*
import kotlin.collections.ArrayList

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
        return CommunicationData.newBuilder()
            .setCommand(command)
            .addAllChannel(channel.map { it.toInt() })
            .setNumberOfExpectedPackets(numberOfExpectedPackets)
            .setNumberOfAcquiredPackets(numberOfAcquiredPackets)
            .setNumberOfReturnedPackets(numberOfReturnedPackets)
            .setNumberOfSendPackets(numberOfSendPackets)
            .addAllData(data.map { it.toInt() })
            .addAllReturnData(returnData.flatten().map { it.toInt() })
            .setDate(date.toInstant().toEpochMilli())
            .build()
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
                communicationData.channelList.map { i -> (i.and(0xFF)).toUByte() }.toUByteArray(),
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

            var command = Commands.values().firstOrNull {it.ordinal == commandApdu[11 + AID.size].toInt()}
            val data: UByteArray = commandApdu.copyOfRange(16 + AID.size, commandApdu.size - 1)

            if (command == null) command = Commands.UNRECOGNIZED

            return CommunicationStruct(
                command,
                commandApdu.copyOfRange(5 + AID.size, 9 + AID.size),
                commandApdu[9 + AID.size].toInt(),
                1,
                0,
                0,
                data,
                ArrayList(),
                Date.from(Instant.now())//change to api call or switch to utc for safety
            )
        }

        fun createEmpty(): CommunicationStruct{
            return CommunicationStruct(
                Commands.UNRECOGNIZED,
                UByteArray(4),
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

