package com.test.securityexample.encryption.util

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val AES_KEY_SIZE = 32
private const val AES_IV_SIZE = 16

class PgpEncryptionUtil(
    private val rsaEncryptionUtil: RSAEncryptionUtil
) : EncryptionUtil<PgpEncryptionUtil.Packet> {

    override suspend fun encrypt(text: String): Packet {
        val random = SecureRandom()
        val keyBytes = ByteArray(AES_KEY_SIZE)
        random.nextBytes(keyBytes)
        val key = SecretKeySpec(keyBytes, "AES")
        val ivBytes = ByteArray(AES_IV_SIZE)
        random.nextBytes(ivBytes)
        val iv = IvParameterSpec(ivBytes)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)
        val encryptedData = cipher.doFinal(text.toBase64())
        val encryptedKeySnapshot = rsaEncryptionUtil.encrypt(
            (keyBytes + ivBytes).encodeToString()
        )
        return Packet(
            data = encryptedData,
            keySnapshot = encryptedKeySnapshot
        )
    }

    override suspend fun decrypt(packet: Packet): String {
        val keyIvBytes = rsaEncryptionUtil.decrypt(packet.keySnapshot).toBase64()
        val keyBytes = ByteArray(AES_KEY_SIZE)
        System.arraycopy(keyIvBytes, 0, keyBytes, 0, AES_KEY_SIZE)
        val key = SecretKeySpec(keyBytes, "AES")
        val ivBytes = ByteArray(AES_IV_SIZE)
        System.arraycopy(keyIvBytes, AES_KEY_SIZE, ivBytes, 0, AES_IV_SIZE)
        val iv = IvParameterSpec(ivBytes)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, key, iv)
        val decryptedData = cipher.doFinal(packet.data)
        return decryptedData.encodeToString()
    }

    override fun clear() {
        rsaEncryptionUtil.clear()
    }

    data class Packet(
        val data: ByteArray,
        val keySnapshot: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Packet

            if (!data.contentEquals(other.data)) return false
            if (!keySnapshot.contentEquals(other.keySnapshot)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = data.contentHashCode()
            result = 31 * result + keySnapshot.contentHashCode()
            return result
        }
    }

}