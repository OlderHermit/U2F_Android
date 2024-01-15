package pl.pja.hce_test

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.util.concurrent.Executor


class MainActivity : AppCompatActivity() {

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    @RequiresApi(Build.VERSION_CODES.R)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val biometricManager = BiometricManager.from(this)

        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(
                        applicationContext,"Authentication error: $errString", Toast.LENGTH_SHORT
                    ).show()
                    disAllowWork()
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Toast.makeText(applicationContext,
                        "Authentication succeeded!", Toast.LENGTH_SHORT)
                        .show()
                    allowWork()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Authentication failed",
                        Toast.LENGTH_SHORT)
                        .show()
                    disAllowWork()
                }
            })


        when (biometricManager.canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS ->
                Log.d("U2F_ANDROID", "App can authenticate using biometrics.")
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                Log.e("U2F_ANDROID", "No biometric features available on this device.")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                Log.e("U2F_ANDROID", "Biometric features are currently unavailable.")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                // Prompts the user to create credentials that your app accepts.
                val enrollIntent = Intent(Settings.ACTION_FINGERPRINT_ENROLL)
                startActivityForResult(enrollIntent, 0)
            }
        }

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()

        findViewById<Button?>(R.id.bt_auth).setOnClickListener {
            biometricPrompt.authenticate(promptInfo)
        }
        findViewById<Button?>(R.id.bt_clear).setOnClickListener {
            shouldClean()
        }

        val runHceIntent = Intent(this, U2FHostApduService::class.java)
        startService(runHceIntent)
        biometricPrompt.authenticate(promptInfo)
    }

    override fun onDestroy() {
        super.onDestroy()
        disAllowWork()
    }

    override fun onStop() {
        super.onStop()
        disAllowWork()
    }

    override fun onStart() {
        super.onStart()
        biometricPrompt.authenticate(promptInfo)
    }

    private fun allowWork() { shouldWork = true; updateViewWork()}
    private fun disAllowWork() { shouldWork = false; updateViewWork()}
    private fun updateViewWork() {
        findViewById<TextView>(R.id.status).text =
            if (shouldWork) resources.getString(R.string.status_unlocked)
            else resources.getString(R.string.status_locked)
    }

    companion object {
        private var shouldWork: Boolean = false
        private var shouldClean: Boolean = false
        fun shouldWork(): Boolean = shouldWork
        fun shouldClean(): Boolean = shouldClean
        fun cleaned() { shouldClean = false }
    }

}

