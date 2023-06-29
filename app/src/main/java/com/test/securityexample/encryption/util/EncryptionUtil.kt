package com.test.securityexample.encryption.util

interface EncryptionUtil<T> {

    suspend fun encrypt(text: String): T
    suspend fun decrypt(encryptedText: T): String
    fun clear()

}

interface ByteArrayEncryptionUtil : EncryptionUtil<ByteArray>