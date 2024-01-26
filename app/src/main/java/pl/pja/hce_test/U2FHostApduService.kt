@file:OptIn(ExperimentalUnsignedTypes::class)

package pl.pja.hce_test

import android.content.SharedPreferences
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import androidx.core.content.edit
import androidx.datastore.core.DataStore
import androidx.datastore.dataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.runBlocking
import pl.pja.hce_test.CommunicationData.Commands
import pl.pja.hce_test.CommunicationData.getDefaultInstance
import pl.pja.hce_test.HostApduServiceUtil.Companion.generateCert
import pl.pja.hce_test.HostApduServiceUtil.Companion.generateKeyHandle
import pl.pja.hce_test.HostApduServiceUtil.Companion.generateKeyPair
import pl.pja.hce_test.HostApduServiceUtil.Companion.RegisterDataStruct
import pl.pja.hce_test.HostApduServiceUtil.Companion.getRegisterDataStruct
import pl.pja.hce_test.HostApduServiceUtil.Companion.saveGeneratedRegister
import pl.pja.hce_test.HostApduServiceUtil.Companion.savePrivateKey
import pl.pja.hce_test.HostApduServiceUtil.Companion.signData
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.util.*


class U2FHostApduService : HostApduService() {
    private lateinit var prefs: SharedPreferences
    private val dataStoreCommunication: DataStore<CommunicationData> by dataStore(
        fileName = "communication_data",
        serializer = CommunicationDataSerializer
    )
    private val dataStoreAliases: DataStore<SavedKeys> by dataStore(
        fileName = "saved_keys_data",
        serializer = SavedKeysSerializer
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
    fun Boolean.toUByte() = if (this) 1u.toUByte() else 0u.toUByte()

    private fun makeResponsePacket(code: UByteArray): ByteArray =
        (ubyteArrayOf(1u) + code).asByteArray()

    private fun makeResponsePacket(count: Int, data:UByteArray, code: UByteArray): ByteArray =
        (ubyteArrayOf(count.toUByte()) + data + code).asByteArray()

    private fun makeResponsePacketNoCount(data:UByteArray, code: UByteArray) : ByteArray =
        (data + code).asByteArray()

    private fun makeOkPacket(): ByteArray =
        (ubyteArrayOf(1u) + STATUS_SUCCESS).asByteArray()

    private fun makeErrorPacket(): ByteArray =
        (ubyteArrayOf(1u) + STATUS_FAILED).asByteArray()

    override fun onCreate() {
        super.onCreate()
        prefs = this.getSharedPreferences("app_counter", MODE_PRIVATE)
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {

        var response = UByteArray(0)
        val statusCheck = checkMessageConstrains(commandApdu.asUByteArray())
        if(!statusCheck.contentEquals(STATUS_SUCCESS))
            return makeOkPacket()

        log("HCE", "processCommandApdu")
        log("HCE", commandApdu.joinToString(" ") { "%02X".format(it) })

        //create struct
        val communicationStruct = CommunicationStruct.createCommunicationStruct(commandApdu.asUByteArray())
        log("HCE", "command ${communicationStruct.command.name}" )

        //decide what to do with packet
        var allDataAcquired = false
        var returnStatusOk = false
        var dataStruct: CommunicationStruct = CommunicationStruct.createEmpty()

        if (MainActivity.shouldClean()){
            runBlocking {
                dataStoreCommunication.updateData {
                    getDefaultInstance()
                }
            }
            MainActivity.cleaned()
            log("HCE", "cleaned cache")
        }

        runBlocking {
            try {
                dataStruct = CommunicationStruct.createCommunicationStruct(dataStoreCommunication.data.first())
                if (!dataStruct.channel.contentEquals(communicationStruct.channel) ||
                    dataStruct.date.time + MAX_TIME_CASHING_DATA < communicationStruct.date.time)
                    throw kotlin.NoSuchElementException()
                if(dataStruct.command != communicationStruct.command &&
                    communicationStruct.command !in arrayOf(Commands.UNRECOGNIZED, Commands.Continue))
                    throw kotlin.NoSuchElementException()
                //same command code but different request
                if (dataStruct.command == communicationStruct.command && dataStruct.returnData.isNotEmpty())
                    throw kotlin.NoSuchElementException()
                //channel ok; time ok; command ok or command unknown or continue
                if (communicationStruct.command == Commands.Continue)
                    returnStatusOk = true //confirmation massage was corrupted

                if ((communicationStruct.command !in arrayOf(Commands.UNRECOGNIZED, Commands.Continue))){
                    dataStruct.addData(communicationStruct.data)
                    dataStoreCommunication.updateData {
                        dataStruct.toCommunicationData()
                    }
                    returnStatusOk = true
                }

            } catch (_: NoSuchElementException){
                if (communicationStruct.command !in arrayOf(Commands.UNRECOGNIZED, Commands.Continue)) {
                    dataStoreCommunication.updateData {
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

        log("HCE", "num of acq ${dataStruct.numberOfAcquiredPackets} expect ${dataStruct.numberOfExpectedPackets}")
        log("HCE", "all data acquired $allDataAcquired returnStatus $returnStatusOk")
        if (!allDataAcquired){
            return if (returnStatusOk)
                makeOkPacket()
            else
                makeErrorPacket()
        }

        when (communicationStruct.command) {
            Commands.Register -> {
                val keyPair : KeyPair = generateKeyPair()
                val challenge: UByteArray = dataStruct.data.copyOfRange(0, 32)
                val appID: UByteArray = dataStruct.data.copyOfRange(32, 64)

                //user public key in X,Y uncompressed format
                val ecPoint: ECPoint = (keyPair.public as ECPublicKey).w
                val x = ecPoint.affineX.toByteArrayOfLength(32)
                val y = ecPoint.affineY.toByteArrayOfLength(32)

                val uncompressedPublicKey = ByteArray(1 + x.size + y.size)
                uncompressedPublicKey[0] = 0x04  // indicates uncompressed format
                System.arraycopy(x, 0, uncompressedPublicKey, 1, x.size)
                System.arraycopy(y, 0, uncompressedPublicKey, 1 + x.size, y.size)

                //TODO probably should also use challenge data to generate cert
                val cert = generateCert(keyPair)

                val handle = generateKeyHandle(KeyStore.getInstance("AndroidKeyStore"), keyPair.private, appID)

                //save
                savePrivateKey(handle, keyPair.private, cert)
                runBlocking {
                    val keyAliases = dataStoreCommunication.data.firstOrNull()
                    if (keyAliases == null){
                        dataStoreAliases.updateData {
                            SavedKeys.getDefaultInstance()
                        }
                    }
                    dataStoreAliases.updateData {
                        it.toBuilder().addKeys(
                            saveGeneratedRegister(handle, dataStruct.data.copyOfRange(33, 65))
                        ).build()
                    }
                }
                var signatureData = UByteArray(0)
                signatureData += 0x00u
                signatureData += dataStruct.data
                signatureData += handle
                signatureData += uncompressedPublicKey.asUByteArray()

                /**
                 * //register response
                 * 0x05        - reserved
                 * 65 bytes    - public key <==> uncompressed X Y values from EC curve (1 byte indicator + 32 X value + 32 Y value)
                 * 1 byte      - length of handle
                 * 1-255 bytes - handle (private key encrypted with MASTER key)
                 * ??? bytes   - certificate in base64 (generated based on private kay)
                 * 71-73 bytes - signature
                 *   0x00        - reserved (RFU)
                 *   32 bytes    - challenge parameters
                 *   32 bytes    - application parameters
                 *   1-255 bytes - handle
                 *   65 bytes    - public key (uncompressed X Y values from EC curve aka)
                 *
                 * size ≈ 420 bytes + handle size
                 */
                response += 0x05u
                response += uncompressedPublicKey.asUByteArray()
                response += handle.size.toUByte()
                response += handle
                response += cert.encoded.asUByteArray()
                //signature
                response += signData(signatureData, KeyStore.getInstance("AndroidKeyStore"), handle)
                response += STATUS_SUCCESS

                dataStruct.generateReturnData(response)
            }
            Commands.Authenticate -> run {
                /**
                 * Auth request
                 * 1 byte - control byte
                 *      0x03 "enforce-user-presence-and-sign"
                 *      0x07 "check-only"
                 *      0x08 "don't-enforce-user-presence-and-sign" same as 0x03 in current version
                 * 32 bytes    - challenge parameters
                 * 32 bytes    - application parameters
                 * 1 byte      - handle length
                 * 1-255 bytes - handle
                 */
                var logInAllowed = true
                val controlByte = dataStruct.data[0]//true control byte is data[1] and will be skipped
                val challenge = dataStruct.data.copyOfRange(2, 34)
                val application = dataStruct.data.copyOfRange(34, 66)
                val handleLength = dataStruct.data[66]
                val handle = dataStruct.data.copyOfRange(67, 67 + handleLength.toInt())

                if (controlByte !in ubyteArrayOf(0x03u, 0x07u, 0x08u)) {
                    log("HCE", "incorrect request code $controlByte")
                    return makeErrorPacket()
                }

                val registerDataStruct: RegisterDataStruct =
                    getRegisterDataStruct(dataStoreAliases, handle)
                        ?: RegisterDataStruct(ubyteArrayOf(), ubyteArrayOf())

                if (registerDataStruct.keyHandle.isEmpty()){
                    log("HCE", "key handle not found")
                    logInAllowed = false
                }else if (!registerDataStruct.appId.contentEquals(application)){
                    log("HCE", "app ids mismatch")
                    log("HCE", "got ${application.joinToString { "%02X".format(it.toInt()) }}")
                    log("HCE", "app ${registerDataStruct.appId.joinToString { "%02X".format(it.toInt()) }}}")

                    logInAllowed = false
                }

                if (controlByte == (0x07).toUByte()){
                    if (logInAllowed)
                        dataStruct.generateReturnData(makeResponsePacket(SW_CONDITIONS_NOT_SATISFIED).asUByteArray())//everything was ok
                    else
                        dataStruct.generateReturnData(makeResponsePacket(SW_WRONG_DATA).asUByteArray())//handle not found
                    return@run
                }

                val counter = prefs.getInt("MainCounter",0)
                prefs.edit {
                    putInt("MainCounter", counter + 1)
                }

                val counterBytes = ubyteArrayOf(
                    counter.ushr(24).and(0xFF).toUByte(),
                    counter.ushr(16).and(0xFF).toUByte(),
                    counter.ushr(8).and(0xFF).toUByte(),
                    counter.and(0xFF).toUByte(),
                )

                var signatureData = UByteArray(0)
                signatureData += application
                signatureData += logInAllowed.toUByte()
                signatureData += counterBytes
                signatureData += challenge

                /**
                 * Auth response
                 * 1 byte   - user presence 1 - authorized, 0 - not
                 * 4 bytes  - counter status
                 * signature
                 *   32 bytes - application parameters
                 *   1 byte   - user presence
                 *   4 bytes  - counter status
                 *   32 bytes - challenge parameters
                 */

                response += logInAllowed.toUByte()
                response += counterBytes
                response += if (registerDataStruct.keyHandle.isEmpty()) signData(signatureData, KeyStore.getInstance("AndroidKeyStore"), registerDataStruct.keyHandle) else signatureData
                response += STATUS_SUCCESS

                dataStruct.generateReturnData(response)
            }
            Commands.Version -> {
                dataStruct.generateReturnData("U2F_V2".encodeToByteArray().asUByteArray() + STATUS_SUCCESS)
            }
            Commands.Echo -> {
                dataStruct.generateReturnData(dataStruct.data)
                log("HCE", "${dataStruct.data}")
            }
            Commands.Continue -> {
                log("HCE", "Continue for ${dataStruct.channel.toList().joinToString { "%02X ".format(it.toInt()) }}")

                val packetNumber = communicationStruct.data[0].toInt()
                if (packetNumber >= dataStruct.returnData.size) {
                    log("HCE", "Error index out of range expected max ${dataStruct.numberOfSendPackets}, got $packetNumber")
                    return makeResponsePacketNoCount(ubyteArrayOf(), STATUS_FAILED)
                }

                dataStruct.numberOfReturnedPackets = packetNumber
                runBlocking {
                    dataStoreCommunication.updateData {
                        dataStruct.toCommunicationData()
                    }
                }
                return makeResponsePacketNoCount(dataStruct.returnData[packetNumber], STATUS_SUCCESS)
            }
            else -> {
                log("HCE", "could not parse code for func %02X".format(commandApdu[12 + AID.size]))
                return makeErrorPacket()
            }
        }

        runBlocking {
            dataStoreCommunication.updateData {
                dataStruct.toCommunicationData()
            }
        }

        log("HCE", "sending first part of response out of ${dataStruct.numberOfSendPackets}")
        return makeResponsePacket(dataStruct.numberOfSendPackets, dataStruct.returnData[0], STATUS_SUCCESS)
    }

    override fun onDeactivated(reason: Int) {
        log("HCE", "Deactivated: $reason")
    }

    companion object {
        private const val DEBUG = false
        const val MAX_DATA_PER_PACKET = 160
        const val MAX_TIME_CASHING_DATA = 5 * 60 * 1000 // 5 min
        //should be changed in xml too
        val AID = ubyteArrayOf(0xF0u, 0x05u, 0x04u, 0x03u, 0x02u, 0x01u, 0xA1u)
        //return codes
        val STATUS_SUCCESS = ubyteArrayOf(0x90u, 0x00u)
        val STATUS_FAILED = ubyteArrayOf(0x6Fu, 0x00u)
        private val SW_CLA_NOT_SUPPORTED = ubyteArrayOf(0x6Eu, 0x00u)
        private val SW_INS_NOT_SUPPORTED = ubyteArrayOf(0x6Du, 0x00u)
        val SW_CONDITIONS_NOT_SATISFIED = ubyteArrayOf(0x69u, 0x85u)
        val SW_WRONG_DATA = ubyteArrayOf(0x6Au, 0x80u)
        //request data
        private const val SELECT_INS : UByte = 0xA4u
        private const val DEFAULT_CLA : UByte = 0x00u
        private val MIN_APDU_LENGTH = 11 + AID.size

        private fun log(tag: String, msg: String) { if (DEBUG) Log.d(tag, msg) }

        //00A4040007F0010203040506101112130300056563686F6563686F6563686F656368...00
        //00 A4 04 00 size AID Cid0 Cid1 Cid2 Cid3 num_of_packets data 0x00
        fun checkMessageConstrains(hexCommandApdu: UByteArray) : UByteArray {
            if (!MainActivity.shouldWork())
                return STATUS_FAILED

            if (hexCommandApdu.size < MIN_APDU_LENGTH)
                return STATUS_FAILED

            if (hexCommandApdu[0] != DEFAULT_CLA)
                return SW_CLA_NOT_SUPPORTED

            if (hexCommandApdu[1] != SELECT_INS)
                return SW_INS_NOT_SUPPORTED

            if (hexCommandApdu[4].toInt() < 5) {
                log("HCE", "too short apdu")
                return STATUS_FAILED
            }

            if (hexCommandApdu[4].toInt() != AID.size) {
                log("HCE", "incorrect AID length")
                return STATUS_FAILED
            }

            if (!hexCommandApdu.copyOfRange(5, 5 + AID.size).contentEquals(AID)) {
                log("HCE", "should have never happened because of xml hardcoded AID")

                return STATUS_FAILED
            }
            return STATUS_SUCCESS
        }
    }
}