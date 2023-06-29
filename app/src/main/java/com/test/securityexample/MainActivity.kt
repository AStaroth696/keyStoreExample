package com.test.securityexample

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.core.content.edit
import androidx.lifecycle.lifecycleScope
import com.test.securityexample.encryption.EncryptionScreen
import com.test.securityexample.encryption.EncryptionScreenState
import com.test.securityexample.encryption.util.AESEncryptionUtil
import com.test.securityexample.encryption.util.AuthenticatedRSAEncryptionUtil
import com.test.securityexample.encryption.util.ByteArrayEncryptionUtil
import com.test.securityexample.encryption.util.PgpEncryptionUtil
import com.test.securityexample.encryption.util.RSAEncryptionUtil
import com.test.securityexample.encryption.util.encodeToString
import com.test.securityexample.encryption.util.toBase64
import com.test.securityexample.ui.theme.SecurityExampleTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

private const val KEY_TEXT = "text"

class MainActivity : ComponentActivity() {

    private val prefs: SharedPreferences by lazy {
        getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
    }
    private lateinit var encryptionUtil: ByteArrayEncryptionUtil
    private val encryptedScreenState: MutableStateFlow<EncryptionScreenState> by lazy {
        MutableStateFlow(getInitialState())
    }
//    private val pgpEncryptionUtil by lazy {
//        PgpEncryptionUtil(
//            rsaEncryptionUtil = RSAEncryptionUtil.create(this)
//        )
//    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        encryptionUtil = AESEncryptionUtil.create(this)
//        encryptionUtil = RSAEncryptionUtil.create(this)
//        encryptionUtil = AuthenticatedRSAEncryptionUtil.create(this)
        setContent {
            SecurityExampleTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val scope = rememberCoroutineScope()
                    EncryptionScreen(
                        stateFlow = encryptedScreenState,
                        onTextChange = { text ->
                            encryptedScreenState.update {
                                it.copy(text = text)
                            }
                        },
                        onEncryptClick = {
                            val text = encryptedScreenState.value.text
                            if (text.isNotBlank()) {
                                scope.launch {
                                    val encrypted = encryptionUtil.encrypt(text)
                                    saveEncryptedText(encryptedText = encrypted)
                                    encryptedScreenState.update {
                                        it.copy(
                                            encryptedBytes = encrypted
                                        )
                                    }
                                }
                            }
                        },
                        onDecryptClick = {
                            val encryptedBytes = encryptedScreenState.value.encryptedBytes
                            if (encryptedBytes?.isNotEmpty() == true) {
                                scope.launch {
                                    val decrypted = encryptionUtil.decrypt(encryptedBytes)
                                    encryptedScreenState.update {
                                        it.copy(
                                            decryptedText = decrypted
                                        )
                                    }
                                }
                            }
                        },
                        onClearClick = {
                            encryptionUtil.clear()
                        }
                    )
                }
            }
        }
        /**
         * PGP packet exchange example
         */
//        lifecycleScope.launch(Dispatchers.IO) {
//            val plainText = "not encrypted text"
//            val packet = pgpEncryptionUtil.encrypt(plainText)
//            println("test___ encrypted: $packet")
//            val decryptedData = pgpEncryptionUtil.decrypt(packet)
//            println("test___ decrypted: $decryptedData")
//        }
    }

    private fun getInitialState(): EncryptionScreenState {
        val savedEncryptedText = getSavedEncryptedText()
        return if (savedEncryptedText.isEmpty()) {
            EncryptionScreenState(
                text = "",
                encryptedBytes = null,
                decryptedText = null
            )
        } else {
            val encryptedTextBytes = savedEncryptedText.toBase64()
            val decryptedText = runBlocking {
                encryptionUtil.decrypt(encryptedTextBytes)
            }
            EncryptionScreenState(
                text = decryptedText,
                encryptedBytes = encryptedTextBytes,
                decryptedText = decryptedText
            )
        }
    }

    private fun getSavedEncryptedText(): String {
        return prefs.getString(KEY_TEXT, null) ?: ""
    }

    private fun saveEncryptedText(encryptedText: ByteArray) {
        prefs.edit {
            putString(KEY_TEXT, encryptedText.encodeToString())
        }
    }
}