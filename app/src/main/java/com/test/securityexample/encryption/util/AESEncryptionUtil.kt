package com.test.securityexample.encryption.util

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import java.math.BigInteger
import java.security.KeyStore
import java.security.KeyStore.SecretKeyEntry
import java.security.SecureRandom
import java.util.Calendar
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal

private const val AES_KEY_ALIAS = "aes_key"
private const val IV_SIZE = 16
private const val IV_PREFS_KEY = "iv"

class AESEncryptionUtil private constructor(
    private val keyStore: KeyStore,
    private val context: Context
) : ByteArrayEncryptionUtil {

    init {
        keyStore.load(null)
    }

    override fun clear() {
        keyStore.deleteEntry(AES_KEY_ALIAS)
        context.getSharedPreferences("ivPrefs", Context.MODE_PRIVATE).edit {
            remove(IV_PREFS_KEY)
        }
    }

    override suspend fun encrypt(text: String): ByteArray {
        val key = getKey()
        val iv = getIv()
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "AndroidKeyStoreBCWorkaround")
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        return cipher.doFinal(text.toBase64())
    }

    override suspend fun decrypt(encryptedText: ByteArray): String {
        val key = getKey()
        val iv = getIv()
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "AndroidKeyStoreBCWorkaround")
        cipher.init(Cipher.DECRYPT_MODE, key, iv)
        return cipher.doFinal(encryptedText).encodeToString()
    }

    private fun getKey(): SecretKey {
        if (!keyStore.containsAlias(AES_KEY_ALIAS)) {
            val notBefore = Calendar.getInstance()
            val notAfter = Calendar.getInstance().apply {
                add(Calendar.YEAR, 1)
            }
            val spec = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            spec.init(
                KeyGenParameterSpec.Builder(
                    AES_KEY_ALIAS,
                    KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
                )
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setKeySize(256)
                    .setKeyValidityStart(notBefore.time)
                    .setKeyValidityEnd(notAfter.time)
                    .setCertificateSubject(X500Principal("CN=test"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setRandomizedEncryptionRequired(false)
                    .build()
            )
            spec.generateKey()
        }
        return (keyStore.getEntry(AES_KEY_ALIAS, null) as SecretKeyEntry).secretKey
    }

    private fun getIv(): IvParameterSpec {
        val prefs = context.getSharedPreferences("ivPrefs", Context.MODE_PRIVATE)
        var iv = prefs.getString(IV_PREFS_KEY, null)?.toIvParameterSpec()
        if (iv == null) {
            val generatedIv = generateIv()
            prefs.edit {
                putString(IV_PREFS_KEY, generatedIv.iv.encodeToString())
            }
            iv = generatedIv
        }
        return iv
    }

    private fun String.toIvParameterSpec(): IvParameterSpec {
        return IvParameterSpec(toBase64())
    }

    private fun generateIv(): IvParameterSpec {
        val ivBytes = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(ivBytes)
        return IvParameterSpec(ivBytes)
    }

    companion object {

        fun create(context: Context): AESEncryptionUtil {
            return AESEncryptionUtil(
                keyStore = KeyStore.getInstance("AndroidKeyStore"), //types can be found here https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keystore-types
                context = context
            )
        }

    }

}

fun String.toBase64(): ByteArray {
    return Base64.decode(this, Base64.NO_WRAP or Base64.NO_PADDING)
}

fun ByteArray.encodeToString(): String {
    return Base64.encodeToString(this, Base64.NO_WRAP or Base64.NO_PADDING)
}