package pl.pja.hce_test

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.time.LocalDate
import java.time.ZoneId
import java.util.*
import java.util.concurrent.atomic.AtomicInteger
import android.content.SharedPreferences
import androidx.core.content.edit
import pl.pja.hce_test.HostApduServiceUtil.Companion.generateCert
import pl.pja.hce_test.HostApduServiceUtil.Companion.generateKeyPair
import pl.pja.hce_test.HostApduServiceUtil.Companion.getNumberOfPacketsAsString
import pl.pja.hce_test.HostApduServiceUtil.Companion.parceHexApdu


class MyHostApduService : HostApduService() {
    //private val dataStore by preferencesDataStore("app_preferences")
    private lateinit var prefs: SharedPreferences

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
        prefs = this.getSharedPreferences("app_preferences", MODE_PRIVATE)
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {

        val data: UByteArray = commandApdu.asUByteArray()
        val response = StringBuilder()
        val hexCommandApdu = toHex(commandApdu)
        val statusCheck = checkMessageConstrains(hexCommandApdu)

        if(statusCheck != STATUS_SUCCESS)
            return hexStringToByteArray("$RETURN_PREAMBLE$STATUS_FAILED")

        /*
        val currentCounterValue= AtomicInteger()
        val exampleCounter = intPreferencesKey("example_counter")
        GlobalScope.launch {
            dataStore.edit { settings ->
                currentCounterValue.set(settings[exampleCounter] ?: 0)
                settings[exampleCounter] = currentCounterValue.get() + 1
            }
        }*//*
        val currentCounterValue = AtomicInteger()
        currentCounterValue.set(prefs.getInt("exampleCounter",0))
        prefs.edit {
            putInt("exampleCounter", currentCounterValue.get() + 1)
        }*/


        //Log.d("HCE", "value of test ${currentCounterValue.get()}")
        Log.d("HCE", "processCommandApdu")
        Log.d("HCE", hexCommandApdu)
        val commandCode: Commands? = Commands.values().firstOrNull {
            it.code == hexCommandApdu[22+AID.length].toString() + hexCommandApdu[22+AID.length+1]
        }

        when (commandCode) {
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
                Log.d("HCE", "pub key: ${toHex(uncompressedPublicKey)} len = ${toHex(uncompressedPublicKey).length/2}")


                val cert = generateCert(keyPair)
                Log.d("HCE", "cert: ${toHex(cert.encoded)} len = ${toHex(cert.encoded).length/2}")


                response.append("05")//reserved
                response.append(toHex(uncompressedPublicKey))
                response.append("05")//to be changed len of handle
                response.append("0102030405")//to be generated
                response.append(toHex(cert.encoded)) //signature
                response.append("00")//RFU
                response.append(hexCommandApdu.substring(36))//change of AID will break it add end?
                response.append("0102030405")//handle again
                response.append(toHex(uncompressedPublicKey))


            }
            Commands.Authenticate -> TODO()
            Commands.Version -> {
                return hexStringToByteArray("${RETURN_PREAMBLE}U2F_V2$STATUS_SUCCESS")
            }
            Commands.Echo -> {
                Log.d("HCE", "Size of request got ${hexCommandApdu.length}")
                prefs.edit().putString("channelid+opretaion code",
                    prefs.getString("channelid+opretaion code", "") + parceHexApdu(hexCommandApdu)
                ).apply()
                //if ("remaining" == "00")
                    //return first part
                return hexStringToByteArray("$RETURN_PREAMBLE$01$STATUS_SUCCESS")
            }
            Commands.Continue -> {
                Log.d("HCE", "Continue for ${hexCommandApdu.substring(14+AID.length,14+8+AID.length)}")
                return hexStringToByteArray("$RETURN_PREAMBLE$STATUS_SUCCESS")
            }
            else -> {
                Log.d("HCE", "could not parce code for func ${hexCommandApdu[10+AID.length].toString() + hexCommandApdu[10+AID.length+1]}")
                return hexStringToByteArray("$RETURN_PREAMBLE$STATUS_FAILED")
            }
        }

        val res = response.toString()
        val numOfPacketsString = getNumberOfPacketsAsString(res.length)

        Log.d("HCE", "response size: ${res.length}")
        Log.d("HCE", "response size: $numOfPacketsString")
        //split to buffer return first part
        for (packet in res.chunked(packetDataSize)) {
            responseBuffer.add("$packet$STATUS_SUCCESS")
        }
        Log.d("HCE", "return : $res")//should be removed for safety reasons
        Log.d("HCE", "actual return : $RETURN_PREAMBLE$numOfPacketsString${res.substring(0,160)}$STATUS_SUCCESS")//should be removed for safety reasons

        return hexStringToByteArray("$RETURN_PREAMBLE$numOfPacketsString${res.substring(0,160.coerceAtMost(res.length))}$STATUS_SUCCESS")
    }

    override fun onDeactivated(reason: Int) {
        Log.d("HCE", "Deactivated: $reason")
    }

    companion object {
        val responseBuffer: Queue<String> = LinkedList()
        const val SUPER_PRIVATE_MASTER_KEY = ""//to be generated
        const val packetDataSize = 160
        const val STATUS_SUCCESS = "9000"
        const val STATUS_FAILED = "6F00"
        const val CLA_NOT_SUPPORTED = "6E00"
        const val INS_NOT_SUPPORTED = "6D00"
        const val RETURN_PREAMBLE = "00a4040007"
        //should be changed in xml too
        const val AID = "F0010203040506"
        const val SELECT_INS = "A4"
        const val DEFAULT_CLA = "00"
        const val MIN_APDU_LENGTH = 12

        enum class Commands(val code: String){
            Register("01"),
            Authenticate("02"),
            Version("03"),
            Continue("04"),
            Echo("05")
        }

        private const val HEX_CHARS = "0123456789ABCDEF"
        private val HEX_CHARS_ARRAY = "0123456789ABCDEF".toCharArray()

        fun hexStringToByteArray(data: String) : ByteArray {

            val result = ByteArray(data.length / 2)

            for (i in data.indices step 2) {
                val firstIndex = HEX_CHARS.indexOf(data[i]);
                val secondIndex = HEX_CHARS.indexOf(data[i + 1]);

                val octet = firstIndex.shl(4).or(secondIndex)
                result[i.shr(1)] = octet.toByte()
            }

            return result
        }

        fun toHex(byteArray: ByteArray) : String {
            val result = StringBuffer()

            byteArray.forEach {
                val octet = it.toInt()
                val firstIndex = (octet and 0xF0).ushr(4)
                val secondIndex = octet and 0x0F
                result.append(HEX_CHARS_ARRAY[firstIndex])
                result.append(HEX_CHARS_ARRAY[secondIndex])
            }

            return result.toString()
        }
        //00 A4 04 00 size AID Cid0 Cid1 Cid2 Cid3 num_of_packets data 0x00
        fun checkMessageConstrains(hexCommandApdu: String) : String {
            if (!MainActivity.shouldWork())
                return STATUS_FAILED

            if (hexCommandApdu.length < MIN_APDU_LENGTH)
                return STATUS_FAILED

            if (hexCommandApdu.substring(0, 2) != DEFAULT_CLA)
                return CLA_NOT_SUPPORTED

            if (hexCommandApdu.substring(2, 4) != SELECT_INS)
                return INS_NOT_SUPPORTED

            if (hexCommandApdu.substring(8, 10).toInt(16) < 5) {
                Log.d("HCE", "too short apdu")
                return STATUS_FAILED
            }

            if (hexCommandApdu.substring(8, 10).toInt(16) != AID.length/2) {
                Log.d("HCE", "incorrect AID length")
                return STATUS_FAILED
            }

            if (hexCommandApdu.substring(10, 10 + AID.length) != AID) {
                Log.d("HCE", "should have never happened because of xml hardcoded AID")
                return STATUS_FAILED
            }
            return STATUS_SUCCESS
        }
    }

}