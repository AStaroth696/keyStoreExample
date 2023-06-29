package com.test.securityexample.encryption

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.test.securityexample.encryption.util.encodeToString
import kotlinx.coroutines.flow.StateFlow

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EncryptionScreen(
    stateFlow: StateFlow<EncryptionScreenState>,
    onTextChange: (String) -> Unit,
    onEncryptClick: () -> Unit,
    onDecryptClick: () -> Unit,
    onClearClick: () -> Unit
) {
    val state by stateFlow.collectAsState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally
    ) {
        TextField(
            value = state.text,
            onValueChange = onTextChange,
            modifier = Modifier.fillMaxWidth()
        )
        Button(onClick = onEncryptClick) {
            Text(text = "Encrypt")
        }
        Text(
            text = state.encryptedBytes?.let(ByteArray::encodeToString) ?: "",
            modifier = Modifier
                .fillMaxWidth()
                .border(4.dp, MaterialTheme.colorScheme.onBackground, RoundedCornerShape(8.dp))
                .padding(8.dp)
        )
        Button(onClick = onDecryptClick) {
            Text(text = "Decrypt")
        }
        Text(
            text = state.decryptedText ?: "",
            modifier = Modifier
                .fillMaxWidth()
                .border(4.dp, MaterialTheme.colorScheme.onBackground, RoundedCornerShape(8.dp))
                .padding(8.dp)
        )
        Button(onClick = onClearClick) {
            Text(text = "Clear")
        }
    }
}