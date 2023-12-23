package pl.pja.hce_test

import android.content.Context
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.preferencesDataStore
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
import java.util.prefs.Preferences
import androidx.datastore.preferences.*
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicInteger
import android.content.SharedPreferences
import androidx.core.content.edit


class MyHostApduService : HostApduService() {
    //private val dataStore by preferencesDataStore("app_preferences")
    private lateinit var prefs: SharedPreferences

    fun BigInteger.toByteArrayOfLength(length: Int): ByteArray {
        val byteArray = ByteArray(length)
        val bytes = this.toByteArray()
        val start = if (bytes.size > length) bytes.size - length else 0
        val end = bytes.size

        // Copy the bytes into the end of the array, leaving the start of the array as zero if the BigInteger is small
        for (i in start until end) {
            byteArray[i + length - end] = bytes[i]
        }

        return byteArray
    }

    override fun onCreate() {
        super.onCreate()
        prefs = this.getSharedPreferences("app_preferences", MODE_PRIVATE)
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {

        val hexCommandApdu = toHex(commandApdu)
        //val response = checkMessageConstrains(hexCommandApdu)

        //if(response[0] != STATUS_SUCCESS[0].code.toByte() && response[1] != STATUS_SUCCESS[1].code.toByte())
        //    return response

        /*
        val currentCounterValue= AtomicInteger()
        val exampleCounter = intPreferencesKey("example_counter")
        GlobalScope.launch {
            dataStore.edit { settings ->
                currentCounterValue.set(settings[exampleCounter] ?: 0)
                settings[exampleCounter] = currentCounterValue.get() + 1
            }
        }*/
        val currentCounterValue = AtomicInteger()
        currentCounterValue.set(prefs.getInt("exampleCounter",0))
        prefs.edit {
            putInt("exampleCounter", currentCounterValue.get() + 1)
        }


        Log.d("HCE", "value of test ${currentCounterValue.get()}")
        Log.d("HCE", "processCommandApdu")
        Log.d("HCE", hexCommandApdu)
        val commandCode: Commands? = Commands.values().firstOrNull {it.code == hexCommandApdu[12+AID.length].toString() + hexCommandApdu[12+AID.length+1] }
        val response = StringBuilder()

        when (commandCode) {
            Commands.Version -> {
                val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
                )
                val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
                    "Test_U2F",
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                ).run {
                    setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    setKeySize(256)
                    build()
                }

                kpg.initialize(parameterSpec)
                val kp = kpg.generateKeyPair()

                val ecPoint: ECPoint = (kp.public as ECPublicKey).w
                val x = ecPoint.affineX.toByteArrayOfLength(32)
                val y = ecPoint.affineY.toByteArrayOfLength(32)

                val uncompressedPublicKey = ByteArray(1 + x.size + y.size)
                uncompressedPublicKey[0] = 0x04  // indicates uncompressed format
                System.arraycopy(x, 0, uncompressedPublicKey, 1, x.size)
                System.arraycopy(y, 0, uncompressedPublicKey, 1 + x.size, y.size)

                Log.d("HCE", "pub key: ${toHex(uncompressedPublicKey)} len = ${toHex(uncompressedPublicKey).length/2}")

                val startDate = Date.from(LocalDate.now().atStartOfDay(ZoneId.systemDefault()).toInstant())
                val endDate = Date.from(LocalDate.now().plusYears(1).atStartOfDay(ZoneId.systemDefault()).toInstant())

                val certBuilder = JcaX509v3CertificateBuilder(
                    X500Name("CN=localhost"),
                    BigInteger.valueOf(1),
                    startDate,
                    endDate,
                    X500Name("CN=localhost"),
                    kp.public
                )
                Log.d("HCE", "value of test ${currentCounterValue.get()}")
                certBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
                certBuilder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign))

                val contentSigner: ContentSigner = JcaContentSignerBuilder("SHA256withECDSA").build(kp.private)

                val certHolder = certBuilder.build(contentSigner)
                val cert = JcaX509CertificateConverter().getCertificate(certHolder)

                Log.d("HCE", "pub key: ${toHex(cert.encoded)} len = ${toHex(cert.encoded).length/2}")

                response.append("05")//reserved
                response.append(toHex(uncompressedPublicKey))
                response.append("05")//to be changed
                response.append("0102030405")//to be generated
                response.append(toHex(cert.encoded))
                //signature
                response.append("00")//RFU
                response.append(hexCommandApdu.substring(36))//change of AID will break it
                response.append("0102030405")//handle again
                response.append(toHex(uncompressedPublicKey))


            }
            Commands.Authenticate -> TODO()
            Commands.Register -> TODO()
            Commands.Continue -> {
                Log.d("HCE", "Continue for ${hexCommandApdu.substring(14+AID.length,14+8+AID.length)}")
                return hexStringToByteArray("00a4040007$STATUS_SUCCESS")
            }
            else -> {
                Log.d("HCE", "could not parce code for func ${hexCommandApdu[10+AID.length].toString() + hexCommandApdu[10+AID.length+1]}")
                return hexStringToByteArray("00a4040007$STATUS_FAILED")
            }
        }

        Log.d("HCE", hexCommandApdu)//should be removed for safety reasons

        val res = response.toString()
        val numOfPackets = (res.length/packetDataSize) + if(res.length % packetDataSize != 0) 1 else 0
        val numOfPacketsString =
            if(numOfPackets < 16)
                "0${numOfPackets.toString(16).uppercase()}"
            else
                numOfPackets.toString(16).uppercase()
        Log.d("HCE", "response size: ${res.length}")
        Log.d("HCE", "response size: $numOfPacketsString")
        //split to buffer return first part
        for (packet in res.chunked(packetDataSize)) {
            responseBuffer.add("$packet$STATUS_SUCCESS")
        }
        Log.d("HCE", "value of test ${currentCounterValue.get()}")
        Log.d("HCE", "return : $res")//should be removed for safety reasons
        Log.d("HCE", "actual return : 00a4040007$numOfPacketsString${res.substring(0,160)}$STATUS_SUCCESS")//should be removed for safety reasons
        //Log.d("HCE", "return : $numOfPacketsString${responseBuffer.element()}")//should be removed for safety reasons
        //return hexStringToByteArray("00a4040007" + responseBuffer.remove()!!)
        return hexStringToByteArray("00a4040007$numOfPacketsString${res.substring(0,160)}$STATUS_SUCCESS")
    }

    override fun onDeactivated(reason: Int) {
        Log.d("HCE", "Deactivated: $reason")
    }

    companion object {
        val responseBuffer: Queue<String> = LinkedList()
        const val packetDataSize = 100
        const val STATUS_SUCCESS = "9000"
        const val STATUS_FAILED = "6F00"
        const val CLA_NOT_SUPPORTED = "6E00"
        const val INS_NOT_SUPPORTED = "6D00"
        //should be changed in xml too
        const val AID = "F0010203040506"
        const val SELECT_INS = "A4"
        const val DEFAULT_CLA = "00"
        const val MIN_APDU_LENGTH = 12

        enum class Commands(val code: String){
            Register("01"),
            Authenticate("02"),
            Version("03"),
            Continue("04")
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

        fun checkMessageConstrains(hexCommandApdu: String) : ByteArray {
            if (!MainActivity.shouldWork())
                return hexStringToByteArray(STATUS_FAILED)

            if (hexCommandApdu.length < MIN_APDU_LENGTH)
                return hexStringToByteArray(STATUS_FAILED)

            if (hexCommandApdu.substring(0, 2) != DEFAULT_CLA)
                return hexStringToByteArray(CLA_NOT_SUPPORTED)

            if (hexCommandApdu.substring(2, 4) != SELECT_INS)
                return hexStringToByteArray(INS_NOT_SUPPORTED)

            if (hexCommandApdu.substring(8, 10).toInt(16) < 5) {
                Log.d("HCE", "too short apdu")
                return hexStringToByteArray(STATUS_FAILED)
            }

            /*if (hexCommandApdu.substring(8, 10).toInt(16) != AID.length) {
                Log.d("HCE", "incorrect AID length")
                return hexStringToByteArray(STATUS_FAILED)
            }*/

            if (hexCommandApdu.substring(10, 10 + AID.length) != AID) {
                Log.d("HCE", "should have never happened because of xml hardcoded AID")
                return hexStringToByteArray(STATUS_FAILED)
            }
            return hexStringToByteArray(STATUS_SUCCESS)
        }

        fun packetLength(data: String): String{
            return (data.length.ushr(8) and 0xFF).toString() + (data.length and 0xFF).toString()
        }
    }

}