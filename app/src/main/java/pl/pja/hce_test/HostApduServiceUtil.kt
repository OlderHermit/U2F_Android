@file:OptIn(ExperimentalUnsignedTypes::class)

package pl.pja.hce_test

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.datastore.core.DataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1Integer
/* import org.bouncycastle.asn1.DERInteger */
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.time.LocalDate
import java.time.ZoneId
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


class HostApduServiceUtil {
    companion object {
        data class RegisterDataStruct(
            val keyHandle: UByteArray,
            val appId: UByteArray
        )

        fun generateKeyPair(): KeyPair {
            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC
            )
            kpg.initialize(256)

            return kpg.generateKeyPair()
        }

        fun savePrivateKey(handle: UByteArray, privateKey: PrivateKey, certificate: X509Certificate){
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            keyStore.setKeyEntry(handle.joinToString {"%02X".format(it.toInt())}, privateKey, null, arrayOf(certificate))
        }

        fun generateCert(keyPair: KeyPair): X509Certificate {
            val startDate = Date
                .from(LocalDate
                    .now()
                    .atStartOfDay(ZoneId.systemDefault())
                    .toInstant()
                )
            val endDate = Date
                .from(LocalDate
                    .now()
                    .plusYears(1)
                    .atStartOfDay(ZoneId.systemDefault())
                    .toInstant()
                )

            val certBuilder = JcaX509v3CertificateBuilder(
                X500Name("CN=localhost"),
                BigInteger.valueOf(1),
                startDate,
                endDate,
                X500Name("CN=localhost"),
                keyPair.public
            )
            certBuilder.addExtension(
                Extension.basicConstraints,
                true,
                BasicConstraints(true)
            )
            certBuilder.addExtension(
                Extension.keyUsage,
                true, KeyUsage(
                    KeyUsage.digitalSignature or KeyUsage.keyCertSign
                )
            )

            val certHolder = certBuilder.build(
                JcaContentSignerBuilder("SHA256withECDSA")
                    .build(keyPair.private)
            )
            return JcaX509CertificateConverter().getCertificate(certHolder)
        }

        fun generateKeyHandle(keyStore: KeyStore, privateKey: PrivateKey): UByteArray {
            keyStore.load(null)

            val alias = "Test_U2F_Master"
            //if (keyStore.containsAlias(alias)) {
            //    Log.d("HCE", "regenerated key")
            //    keyStore.deleteEntry(alias)
            //}

            val masterKey: SecretKey = (
                    if (!keyStore.containsAlias(alias)) {
                        val kg: KeyGenerator = KeyGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_AES,
                            "AndroidKeyStore"
                        )
                        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_ENCRYPT
                        ).run {
                            setDigests(KeyProperties.DIGEST_SHA512)
                            setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            setKeySize(256)
                            build()
                        }

                        kg.init(parameterSpec)
                        kg.generateKey()
                    } else {
                        keyStore.getKey(alias, null) as SecretKey
                    }
                    )

            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
            cipher.init(Cipher.ENCRYPT_MODE, masterKey)

            return cipher.doFinal(privateKey.encoded).asUByteArray()
        }

        fun saveGeneratedRegister(handle: UByteArray, appId: UByteArray): SavedKeys.Key {
            return SavedKeys.Key.newBuilder()
                .addAllKeyHandle(handle.map { it.toInt() })
                .addAllAppId(appId.map { it.toInt() })
                .build()
        }

        fun getRegisterDataStruct(store: DataStore<SavedKeys>, handle: UByteArray): RegisterDataStruct?{
            val test = handle.map { it.toInt() }
            var res = SavedKeys.Key.getDefaultInstance()
            runBlocking {
                //first() should never find null (if null register should generate new instance)
                //store.data.first().keysList.forEach { Log.d("HCE", "saved handle: ${it.keyHandleList.joinToString { it1 -> "%02X".format(it1.toInt())} }")}
                res = store.data.first().keysList.firstOrNull { it.keyHandleList == test }
            }
            return if(res != null)
                RegisterDataStruct(
                    res.keyHandleList.map { it.toUByte() }.toUByteArray(),
                    res.appIdList.map { it.toUByte() }.toUByteArray()
                )
            else
                null
        }

        fun signData(data: UByteArray, keyStore: KeyStore, handle: UByteArray): UByteArray {
            keyStore.load(null)

            val key = keyStore.getKey(handle.joinToString {"%02X".format(it.toInt())}, null) as PrivateKey
            val signature: ByteArray = Signature.getInstance("ECDSA").run {//prev SHA256withECDSA
                initSign(key)
                update(data.asByteArray())
                sign()
            }

            val len: Int = signature.size / 2

            val rBytes: ByteArray = signature.copyOfRange(0, len)
            val sBytes: ByteArray = signature.copyOfRange(len, signature.size)

            return encodeSignature(BigInteger(1, rBytes), BigInteger(1, sBytes))

            //return signature.asUByteArray()
        }

        private fun encodeSignature(r: BigInteger, s: BigInteger): UByteArray =
            DERSequence(arrayOf(ASN1Integer(r), ASN1Integer(s))).encoded.asUByteArray()
    }
}