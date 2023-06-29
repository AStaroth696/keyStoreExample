package com.test.securityexample.encryption.util

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.hardware.biometrics.BiometricPrompt.AuthenticationCallback
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.suspendCancellableCoroutine
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.Calendar
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val PROVIDER = "AndroidKeyStore"
private const val CIPHER_PROVIDER = "AndroidKeyStoreBCWorkaround"
private const val AUTHENTICATED_RSA_KEY_ALIAS = "auth_rsa_key"
private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_ECB
private const val PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"

class AuthenticatedRSAEncryptionUtil private constructor(
    private val keyStore: KeyStore,
    private val activity: ComponentActivity
) : ByteArrayEncryptionUtil {

    private val keyguardManager: KeyguardManager by lazy {
        activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    }
    private var launcherDeferred: CompletableDeferred<Boolean>? = null
    private val launcher =
        activity.registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            launcherDeferred?.complete(it.resultCode == Activity.RESULT_OK)
        }

    init {
        keyStore.load(null)
    }

    override suspend fun encrypt(text: String): ByteArray {
        assertScreenLockSet()
        authenticate()
        val key = getKey()
        val cipher = Cipher.getInstance(TRANSFORMATION, CIPHER_PROVIDER)
        cipher.init(Cipher.ENCRYPT_MODE, key.public)
        return cipher.doFinal(text.toByteArray())
    }

    private fun assertScreenLockSet() {
        if (!keyguardManager.isDeviceSecure) throw IllegalAccessException(
            "Unable to use authenticated keystore without setting screen lock protection"
        )
    }

    private suspend fun authenticate() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            suspendCancellableCoroutine { continuation ->
                BiometricPrompt.Builder(activity)
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setTitle("KeyStore authentication")
                    .setNegativeButton("Cancel", Executors.newSingleThreadExecutor()) { _, _ -> }
                    .build()
                    .authenticate(
                        CancellationSignal(),
                        Executors.newSingleThreadExecutor(),
                        object : AuthenticationCallback() {
                            override fun onAuthenticationError(
                                errorCode: Int,
                                errString: CharSequence?
                            ) {
                                continuation.resumeWithException(RuntimeException(errString?.toString()))
                            }

                            override fun onAuthenticationHelp(
                                helpCode: Int,
                                helpString: CharSequence?
                            ) {
                                super.onAuthenticationHelp(helpCode, helpString)
                                continuation.resumeWithException(RuntimeException(helpString?.toString()))
                            }

                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                                super.onAuthenticationSucceeded(result)
                                continuation.resume(Unit)
                            }

                            override fun onAuthenticationFailed() {
                                super.onAuthenticationFailed()
                                continuation.resumeWithException(RuntimeException("Authentication failed"))
                            }
                        }
                    )
            }
        } else {
            val intent = keyguardManager.createConfirmDeviceCredentialIntent(
                "Authentication request",
                "Authentication required to obtain user secret."
            )
            launcherDeferred = CompletableDeferred()
            launcher.launch(intent)
            val result = launcherDeferred?.await()
            launcherDeferred = null
            if (result != true) throw IllegalAccessException("User not authenticated")
        }
    }

    private fun getKey(): KeyPair {
        if(!keyStore.containsAlias(AUTHENTICATED_RSA_KEY_ALIAS)) {
            val notBefore = Calendar.getInstance()
            val notAfter = Calendar.getInstance().apply {
                add(Calendar.YEAR, 1)
            }
            val spec = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER)
            spec.initialize(
                KeyGenParameterSpec.Builder(
                    AUTHENTICATED_RSA_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                ).setEncryptionPaddings(PADDING)
                    .setBlockModes(BLOCK_MODE)
                    .setKeySize(2048)
                    .setKeyValidityStart(notBefore.time)
                    .setKeyValidityEnd(notAfter.time)
                    .setUserAuthenticationRequired(true)
                    .apply {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            setUserAuthenticationParameters(5, KeyProperties.AUTH_BIOMETRIC_STRONG)
                        } else {
                            setUserAuthenticationValidityDurationSeconds(5)
                        }
                    }
                    .setCertificateSubject(X500Principal("CN=test"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .build()
            )
            spec.generateKeyPair()
        }
        val keyPairEntry = keyStore.getEntry(AUTHENTICATED_RSA_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        return KeyPair(keyPairEntry.certificate.publicKey, keyPairEntry.privateKey)
    }

    override suspend fun decrypt(encryptedText: ByteArray): String {
        assertScreenLockSet()
        authenticate()
        val key = getKey()
        val cipher = Cipher.getInstance(TRANSFORMATION, CIPHER_PROVIDER)
        cipher.init(Cipher.DECRYPT_MODE, key.private)
        return String(cipher.doFinal(encryptedText))
    }

    override fun clear() {
        keyStore.deleteEntry(AUTHENTICATED_RSA_KEY_ALIAS)
    }

    companion object {

        fun create(activity: ComponentActivity): AuthenticatedRSAEncryptionUtil {
            return AuthenticatedRSAEncryptionUtil(
                keyStore = KeyStore.getInstance(PROVIDER),
                activity = activity
            )
        }
    }

}