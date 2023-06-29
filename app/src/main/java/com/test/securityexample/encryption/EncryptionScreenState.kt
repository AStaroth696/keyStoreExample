package com.test.securityexample.encryption

data class EncryptionScreenState(
    val text: String,
    val encryptedBytes: ByteArray?,
    val decryptedText: String?
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptionScreenState

        if (text != other.text) return false
        if (!encryptedBytes.contentEquals(other.encryptedBytes)) return false
        if (decryptedText != other.decryptedText) return false

        return true
    }

    override fun hashCode(): Int {
        var result = text.hashCode()
        result = 31 * result + encryptedBytes.contentHashCode()
        result = 31 * result + decryptedText.hashCode()
        return result
    }

}
