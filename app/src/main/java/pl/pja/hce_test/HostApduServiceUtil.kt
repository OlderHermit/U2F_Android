@file:OptIn(ExperimentalUnsignedTypes::class)

package pl.pja.hce_test

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.datastore.core.DataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
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
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.*
import javax.crypto.Cipher
import kotlin.math.pow

class HostApduServiceUtil {
    companion object {
        data class KeyAliasStruct(
            val alias: String,
            val keyHandle: UByteArray,
            val appId: UByteArray
        )

        fun generateKeyPair(): Pair<KeyPair, String> {
            val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            val alias : String = "Test_U2F_${Instant.now().toEpochMilli()}_${(Math.random()* 10.0.pow(Math.random() * 101)).toInt()}"
            val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).run {
                setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                setKeySize(256)
                build()
            }

            kpg.initialize(parameterSpec)

            return Pair<KeyPair, String>(kpg.generateKeyPair(), alias)
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

            val masterKey: Key = (
                    if (!keyStore.containsAlias(alias)) {
                        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_AES,
                            "AndroidKeyStore"
                        )
                        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_ENCRYPT
                        ).run {
                            setDigests(KeyProperties.DIGEST_SHA512)
                            build()
                        }

                        kpg.initialize(parameterSpec)
                        //public == private because of AES algorithm
                        kpg.generateKeyPair().private
                    } else {
                        keyStore.getKey(alias, null)
                    }
                    )
            val cipher = Cipher.getInstance(masterKey.algorithm)
            cipher.init(Cipher.ENCRYPT_MODE, masterKey)

            return cipher.doFinal(privateKey.encoded).asUByteArray()
        }

        fun generateKeyAlias(alias: String, handle: UByteArray, appId: UByteArray): KeyAliases.KeyAlias {
            return KeyAliases.KeyAlias.newBuilder()
                .setAlias(alias)
                .addAllKeyHandle(handle.map { it.toInt() })
                .addAllAppId(appId.map { it.toInt() })
                .build()
        }

        fun getKeyAliasStruct(store: DataStore<KeyAliases>, handle: UByteArray): KeyAliasStruct?{
            val test = handle.map { it.toInt() }
            var res = KeyAliases.KeyAlias.getDefaultInstance()
            runBlocking {
                //first() should never find null (if null register should generate new instance)
                res = store.data.first().dataList.firstOrNull { it.keyHandleList == test }
            }
            return if(res != null)
                KeyAliasStruct(
                    res.alias,
                    res.keyHandleList.map { it.toUByte() }.toUByteArray(),
                    res.appIdList.map { it.toUByte() }.toUByteArray()
                )
            else
                null
        }

        fun signData(data: UByteArray, keyStore: KeyStore, keyAlias: String): UByteArray {
            keyStore.load(null)

            val key: Key = keyStore.getKey(keyAlias, null)
            val cipher = Cipher.getInstance(key.algorithm)
            cipher.init(Cipher.ENCRYPT_MODE, key)

            return cipher.doFinal(data.asByteArray()).asUByteArray()
        }
    }
}