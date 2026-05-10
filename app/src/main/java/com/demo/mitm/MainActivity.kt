package com.demo.mitm

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.File

class MainActivity : ComponentActivity() {

    // ✅ HARDENED: Certificate pin khớp với server_hard.js
    private val SERVER_PIN = "sha256/IEO7ldA4qBREHbkEAZHhadBW5ZW0GflT6aihRYNkoYA="

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isRooted())   Log.w("SECURITY", "Root detected!")
        if (isProxySet()) Log.w("SECURITY", "Proxy detected!")
        setContent { MaterialTheme { LoginScreen() } }
    }

    private fun isRooted(): Boolean =
        listOf("/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/system/app/Superuser.apk").any { File(it).exists() }

    private fun isProxySet(): Boolean =
        !System.getProperty("http.proxyHost").isNullOrBlank()

    // ✅ HARDENED: Dùng CertificatePinner thay vì trustAllCerts
    private fun getHardenedClient(): OkHttpClient {
        val certificatePinner = CertificatePinner.Builder()
            .add("10.0.2.2", SERVER_PIN)
            .build()
        return OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .hostnameVerifier { _, _ -> true }
            .build()
    }

    fun login(user: String, pass: String, onResult: (Boolean, String) -> Unit) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val body = JSONObject()
                    .put("username", user)
                    .put("password", pass)
                    .toString()
                    .toRequestBody("application/json".toMediaType())

                val req = Request.Builder()
                    .url("https://10.0.2.2:3000/api/login")
                    .post(body).build()

                val resp     = getHardenedClient().newCall(req).execute()
                val respBody = resp.body?.string() ?: ""
                val json     = JSONObject(respBody)

                if (json.optString("status") == "ok") {
                    val token = json.optString("token")

                    // ✅ HARDENED: Lưu token bằng EncryptedSharedPreferences (AES-256-GCM)
                    // Không còn lưu plaintext vào token.txt
                    val masterKey = MasterKey.Builder(this@MainActivity)
                        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                        .build()
                    val prefs = EncryptedSharedPreferences.create(
                        this@MainActivity,
                        "secure_prefs",
                        masterKey,
                        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                    )
                    prefs.edit().putString("auth_token", token).apply()
                    Log.d("SECURITY", "Token saved securely (encrypted)")

                    withContext(Dispatchers.Main) { onResult(true, "Token secured!") }
                } else {
                    withContext(Dispatchers.Main) { onResult(false, "Invalid credentials") }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { onResult(false, e.message ?: "Error") }
            }
        }
    }
}

@Composable
fun LoginScreen() {
    val activity = androidx.compose.ui.platform.LocalContext.current as MainActivity
    var username  by remember { mutableStateOf("admin") }
    var password  by remember { mutableStateOf("Secret@123") }
    var status    by remember { mutableStateOf("") }
    var token     by remember { mutableStateOf("") }
    var isOk      by remember { mutableStateOf(false) }
    var loading   by remember { mutableStateOf(false) }

    val green  = Color(0xFF16A34A)
    val red    = Color(0xFFDC2626)
    val blue   = Color(0xFF1D4ED8)
    val gray50 = Color(0xFFF8FAFC)
    val gray200= Color(0xFFE2E8F0)
    val gray600= Color(0xFF475569)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White)
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        // ── Header ──
        Text("🔐", fontSize = 48.sp)
        Spacer(Modifier.height(8.dp))
        Text(
            "Secure Banking App",
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = Color(0xFF0F172A)
        )
        Text(
            "MITM Demo — Project 4",
            fontSize = 12.sp,
            color = gray600
        )
        Spacer(Modifier.height(32.dp))

        // ── Username ──
        OutlinedTextField(
            value = username,
            onValueChange = { username = it },
            label = { Text("Username") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp)
        )
        Spacer(Modifier.height(12.dp))

        // ── Password ──
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp)
        )
        Spacer(Modifier.height(20.dp))

        // ── Login Button ──
        Button(
            onClick = {
                loading = true
                status  = "Connecting..."
                token   = ""
                activity.login(username, password) { ok, msg ->
                    loading = false
                    isOk    = ok
                    status  = if (ok) "✓ Login successful — Token encrypted!" else "✗ $msg"
                    if (ok) token = msg
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.buttonColors(containerColor = blue),
            enabled = !loading
        ) {
            if (loading)
                CircularProgressIndicator(
                    color = Color.White,
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp
                )
            else
                Text("Login", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
        }

        // ── Status ──
        if (status.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        if (isOk) green.copy(alpha = 0.08f) else red.copy(alpha = 0.08f),
                        RoundedCornerShape(8.dp)
                    )
                    .border(
                        1.dp,
                        if (isOk) green.copy(alpha = 0.3f) else red.copy(alpha = 0.3f),
                        RoundedCornerShape(8.dp)
                    )
                    .padding(12.dp)
            ) {
                Text(
                    status,
                    color = if (isOk) green else red,
                    fontWeight = FontWeight.Medium,
                    fontSize = 14.sp
                )
            }
        }

        // ── Security info box (hiện sau login thành công) ──
        if (isOk) {
            Spacer(Modifier.height(12.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(green.copy(alpha = 0.05f), RoundedCornerShape(8.dp))
                    .border(1.dp, green.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                Text(
                    "✅ Token lưu EncryptedSharedPreferences (AES-256-GCM)",
                    fontSize = 11.sp,
                    color = green,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "ADB shell không đọc được — Android Keystore protected",
                    fontSize = 11.sp,
                    color = gray600,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}