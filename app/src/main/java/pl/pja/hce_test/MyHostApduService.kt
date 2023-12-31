@file:OptIn(ExperimentalUnsignedTypes::class)

package pl.pja.hce_test

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.dataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import pl.pja.hce_test.CommunicationData.Commands
import pl.pja.hce_test.CommunicationData.getDefaultInstance
import pl.pja.hce_test.HostApduServiceUtil.Companion.generateCert
import pl.pja.hce_test.HostApduServiceUtil.Companion.generateKeyHandle
import pl.pja.hce_test.HostApduServiceUtil.Companion.generateKeyPair
import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.util.*


class MyHostApduService : HostApduService() {
    private val dataStore: DataStore<CommunicationData> by dataStore(
        fileName = "communication_data",
        serializer = CommunicationDataSerializer
    )

    private fun BigInteger.toByteArrayOfLength(length: Int): ByteArray {
        val byteArray = ByteArray(length)
        val bytes = this.toByteArray()
        val start = if (bytes.size > length) bytes.size - length else 0
        val end = bytes.size

        for (i in start until end) {
            byteArray[i + length - end] = bytes[i]
        }

        return byteArray
    }

    override fun onCreate() {
        super.onCreate()
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {

        var response = UByteArray(0)
        val statusCheck = checkMessageConstrains(commandApdu.asUByteArray())

        if(!statusCheck.contentEquals(STATUS_SUCCESS))
            return (RETURN_PREAMBLE + 0x01u + STATUS_FAILED).toByteArray()

        Log.d("HCE", "processCommandApdu")
        Log.d("HCE", commandApdu.joinToString(" ") { "%02X".format(it) })

        //create struct
        val communicationStruct = CommunicationStruct.createCommunicationStruct(commandApdu.asUByteArray())
        Log.d("HCE", "command ${communicationStruct.command.name}" )
        Log.d("HCE", "$communicationStruct" )
        /**
        //czy miałem taki channel
            //nie
                //zapisz nowy strukt
            //tak
                //czy time out < 5 min
                    //tak
                        //czy resend
                            //nie
                                //dodaj dane do starego struct i return ok
                            //tak
                                //czy pakiet ma wypełnione return data
                                    //tak
                                        //return normalnie resend
                                    //nie
                                        //return domyśle ok (wysłanie danych nie koćzy się błędem w aktualnej wersji)
                    //nie
                        //czy resend
                            //tak
                                //return timed-out
                            //nie
                                //nadpisz stary nowym struct
        */


        //decide what to do with packet
        var allDataAcquired = false
        var returnStatusOk = false
        var dataStruct: CommunicationStruct = CommunicationStruct.createEmpty()

        if (MainActivity.shouldClean()){
            runBlocking {
                dataStore.updateData {
                    getDefaultInstance()
                }
            }
            MainActivity.cleaned()
            Log.d("HCE", "cleaned cache")
        }

        runBlocking {
            try {
                dataStruct = CommunicationStruct.createCommunicationStruct(dataStore.data.first())
                if (!dataStruct.channel.contentEquals(communicationStruct.channel) ||
                    dataStruct.date.time + MAX_TIME_CASHING_DATA < communicationStruct.date.time)
                    throw kotlin.NoSuchElementException()
                if(dataStruct.command != communicationStruct.command &&
                    communicationStruct.command !in arrayOf(Commands.UNRECOGNIZED, Commands.Continue))
                    throw kotlin.NoSuchElementException()

                //channel ok; time ok; command ok or command unknown or continue
                if (communicationStruct.command == Commands.Continue)
                    returnStatusOk = true //confirmation massage was corrupted

                if ((communicationStruct.command !in arrayOf(Commands.UNRECOGNIZED, Commands.Continue))){
                    Log.d("HCE", "data added")
                    dataStruct.addData(communicationStruct.data)
                    dataStore.updateData {
                        dataStruct.toCommunicationData()
                    }
                    returnStatusOk = true
                }

            } catch (_: NoSuchElementException){
                Log.d("HCE", "caught")
                if (communicationStruct.command !in arrayOf(Commands.UNRECOGNIZED, Commands.Continue)) {
                    dataStore.updateData {
                        communicationStruct.toCommunicationData()
                    }
                    dataStruct = communicationStruct
                    returnStatusOk = true
                }
            }
        }

        if (dataStruct.numberOfAcquiredPackets == dataStruct.numberOfExpectedPackets && dataStruct.numberOfExpectedPackets != 0){
            allDataAcquired = true
        }

        //Log.d("HCE", "channel $dataStruct")
        Log.d("HCE", "num of acq ${dataStruct.numberOfAcquiredPackets} expect ${dataStruct.numberOfExpectedPackets}")
        Log.d("HCE", "all data acquired $allDataAcquired returnStatus $returnStatusOk")
        if (!allDataAcquired){
            return if (returnStatusOk)
                (RETURN_PREAMBLE + 0x01u + STATUS_SUCCESS).asByteArray()
            else
                (RETURN_PREAMBLE + 0x01u + STATUS_FAILED).asByteArray()
        }

        when (communicationStruct.command) {
            Commands.Register -> {
                val keyPair = generateKeyPair()

                //user public key in X,Y uncompressed format
                val ecPoint: ECPoint = (keyPair.public as ECPublicKey).w
                val x = ecPoint.affineX.toByteArrayOfLength(32)
                val y = ecPoint.affineY.toByteArrayOfLength(32)

                val uncompressedPublicKey = ByteArray(1 + x.size + y.size)
                uncompressedPublicKey[0] = 0x04  // indicates uncompressed format
                System.arraycopy(x, 0, uncompressedPublicKey, 1, x.size)
                System.arraycopy(y, 0, uncompressedPublicKey, 1 + x.size, y.size)
                Log.d("HCE", "pub key: ${uncompressedPublicKey.joinToString { "%02X ".format(it.toInt()) }} len = ${uncompressedPublicKey.size}")

                //TODO probably should use challenge data to generate cert
                //TODO permanent save of generated credential
                val cert = generateCert(keyPair)
                Log.d("HCE", "cert: ${cert.encoded.joinToString { "%02X ".format(it.toInt()) }} len = ${cert.encoded.size}")

                val handle = ubyteArrayOf(0x10u, 0x11u, 0x10u, 0x11u, 0x10u)//generateKeyHandle(keyPair.private)

                /**
                 * //register response
                 * 0x05        - reserved
                 * 65 bytes    - public key <==> uncompressed X Y values from EC curve (1 byte indicator + 32 X value + 32 Y value)
                 * 1 byte      - length of handle
                 * 1-255 bytes - handle (private key encrypted with MASTER key)
                 * ??? bytes   - certificate in base64 (generated based on private kay)
                 * //signature
                 * 0x00        - reserved (RFU)
                 * 32 bytes    - challenge parameters
                 * 32 bytes    - application id
                 * 1-255 bytes - handle
                 * 65 bytes    - public key (uncompressed X Y values from EC curve aka)
                 *
                 * size = 900 bytes + 2 x handle size
                 */
                response += 0x05u
                response += uncompressedPublicKey.asUByteArray()
                response += handle.size.toUByte()
                response += handle
                response += cert.encoded.asUByteArray()
                response += 0x00u
                response += dataStruct.data
                response += handle
                response += uncompressedPublicKey.asUByteArray()
                response += STATUS_SUCCESS

                dataStruct.generateReturnData(response)
            }
            Commands.Authenticate -> TODO()
            Commands.Version -> {
                dataStruct.generateReturnData("U2F_V2".encodeToByteArray().asUByteArray() + STATUS_SUCCESS)
            }
            Commands.Echo -> {
                dataStruct.generateReturnData(dataStruct.data)
                Log.d("HCE", "${dataStruct.data}")
                Log.d("HCE", "${dataStruct.returnData}")
            }
            Commands.Continue -> {
                Log.d("HCE", "Continue for ${dataStruct.channel.toList().joinToString { "%02X ".format(it.toInt()) }}")

                val packetNumber = communicationStruct.data[0].toInt()
                if (packetNumber >= dataStruct.returnData.size) {
                    Log.d("HCE", "Error index out of range expected max ${dataStruct.numberOfSendPackets}, got $packetNumber")
                    return (RETURN_PREAMBLE + STATUS_FAILED).asByteArray()
                }

                dataStruct.numberOfReturnedPackets = packetNumber
                runBlocking {
                    dataStore.updateData {
                        dataStruct.toCommunicationData()
                    }
                }
                Log.d("HCE", "return ${dataStruct.returnData[packetNumber].joinToString(" "){"%02X".format(it.toInt())}}")
                return (RETURN_PREAMBLE + dataStruct.returnData[packetNumber] + STATUS_SUCCESS).asByteArray()
            }
            else -> {
                Log.d("HCE", "could not parce code for func %02X".format(commandApdu[12 + AID.size]))
                return (RETURN_PREAMBLE + 0x01u + STATUS_FAILED).asByteArray()
            }
        }

        runBlocking {
            dataStore.updateData {
                dataStruct.toCommunicationData()
            }
        }

        Log.d("HCE", "sending first part of response out of ${dataStruct.numberOfSendPackets}")
        Log.d("HCE", "return ${dataStruct.returnData[0].joinToString(" "){"%02X".format(it.toInt())}}")
        return (RETURN_PREAMBLE + dataStruct.numberOfSendPackets.toUByte() + dataStruct.returnData[0] + STATUS_SUCCESS).asByteArray()
    }

    override fun onDeactivated(reason: Int) {
        Log.d("HCE", "Deactivated: $reason")
    }

    companion object {
        const val SUPER_PRIVATE_MASTER_KEY = ""//to be generated
        const val MAX_DATA_PER_PACKET = 160
        const val MAX_TIME_CASHING_DATA = 5 * 60 * 1000 // 5 min
        val STATUS_SUCCESS = ubyteArrayOf(0x90u, 0x00u)
        val STATUS_FAILED = ubyteArrayOf(0x6Fu, 0x00u)
        private val CLA_NOT_SUPPORTED = ubyteArrayOf(0x6Eu, 0x00u)
        private val INS_NOT_SUPPORTED = ubyteArrayOf(0x6Du, 0x00u)
        val RETURN_PREAMBLE = ubyteArrayOf(0x00u, 0xA4u, 0x04u, 0x00u, 0x07u)
        //should be changed in xml too
        val AID = ubyteArrayOf(0xF0u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u)
        private const val SELECT_INS : UByte = 0xA4u
        private const val DEFAULT_CLA : UByte = 0x00u
        private const val MIN_APDU_LENGTH = 12

        /*enum class Commands(val code: String){
            Register("01"),
            Authenticate("02"),
            Version("03"),
            Continue("04"),
            Echo("05")
        }*/
        //00A4040007F0010203040506101112130300056563686F6563686F6563686F656368
        //00 A4 04 00 size AID Cid0 Cid1 Cid2 Cid3 num_of_packets data (0x00)?
        fun checkMessageConstrains(hexCommandApdu: UByteArray) : UByteArray {
            if (!MainActivity.shouldWork())
                return STATUS_FAILED

            if (hexCommandApdu.size < MIN_APDU_LENGTH)
                return STATUS_FAILED

            if (hexCommandApdu[0] != DEFAULT_CLA)
                return CLA_NOT_SUPPORTED

            if (hexCommandApdu[1] != SELECT_INS)
                return INS_NOT_SUPPORTED

            if (hexCommandApdu[4].toInt() < 5) {
                Log.d("HCE", "too short apdu")
                return STATUS_FAILED
            }

            if (hexCommandApdu[4].toInt() != AID.size) {
                Log.d("HCE", "incorrect AID length")
                return STATUS_FAILED
            }

            if (!hexCommandApdu.copyOfRange(5, 5 + AID.size).contentEquals(AID)) {
                Log.d("HCE", "should have never happened because of xml hardcoded AID")

                return STATUS_FAILED
            }
            return STATUS_SUCCESS
        }
    }
}