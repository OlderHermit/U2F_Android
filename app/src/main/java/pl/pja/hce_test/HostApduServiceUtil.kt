@file:OptIn(ExperimentalUnsignedTypes::class)

package pl.pja.hce_test

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.LocalDate
import java.time.ZoneId
import java.util.*

class HostApduServiceUtil {
    companion object {
        fun generateKeyPair(): KeyPair {
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
            return kpg.generateKeyPair()
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

        fun generateKeyHandle(privateKey: PrivateKey): UByteArray {
            TODO()
        }
    }
}