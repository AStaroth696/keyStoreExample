package com.test.securityexample.encryption.util

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import java.util.Calendar
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

private const val PROVIDER = "AndroidKeyStore"
private const val CIPHER_PROVIDER = "AndroidKeyStoreBCWorkaround"
private const val RSA_KEY_ALIAS = "rsa_key"
private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_ECB
private const val PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"

class RSAEncryptionUtil private constructor(
    private val keyStore: KeyStore
) : ByteArrayEncryptionUtil {

    init {
        keyStore.load(null)
    }

    override fun clear() {
        keyStore.deleteEntry(RSA_KEY_ALIAS)
    }

    override suspend fun encrypt(text: String): ByteArray {
        val key = getKey()
        val cipher = Cipher.getInstance(TRANSFORMATION, CIPHER_PROVIDER)
        cipher.init(Cipher.ENCRYPT_MODE, key.public)
        return cipher.doFinal(text.toByteArray())
    }

    private fun getKey(): KeyPair {
        if(!keyStore.containsAlias(RSA_KEY_ALIAS)) {
            val notBefore = Calendar.getInstance()
            val notAfter = Calendar.getInstance().apply {
                add(Calendar.YEAR, 1)
            }
            val spec = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER)
            spec.initialize(
                KeyGenParameterSpec.Builder(
                    RSA_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                ).setEncryptionPaddings(PADDING)
                    .setBlockModes(BLOCK_MODE)
                    .setKeySize(2048)
                    .setKeyValidityStart(notBefore.time)
                    .setKeyValidityEnd(notAfter.time)
                    .setCertificateSubject(X500Principal("CN=test"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .build()
            )
            spec.generateKeyPair()
        }
        val keyPairEntry = keyStore.getEntry(RSA_KEY_ALIAS, null) as PrivateKeyEntry
        return KeyPair(keyPairEntry.certificate.publicKey, keyPairEntry.privateKey)
    }

    override suspend fun decrypt(encryptedText: ByteArray): String {
        val key = getKey()
        val cipher = Cipher.getInstance(TRANSFORMATION, CIPHER_PROVIDER)
        cipher.init(Cipher.DECRYPT_MODE, key.private)
        return String(cipher.doFinal(encryptedText))
    }

    companion object {

        fun create(context: Context): RSAEncryptionUtil {
            return RSAEncryptionUtil(
                keyStore = KeyStore.getInstance(PROVIDER)
            )
        }
    }
}