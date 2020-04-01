package com.yslvlln.encryptionlib

import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class Decrypt {
    companion object {
        fun decrypt(ciphertext: String, secretkey: String, salt: String): String? {
            try {
                val iv = ByteArray(16)
                val ivspec = IvParameterSpec(iv)
                val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                val spec = PBEKeySpec(secretkey.toCharArray(), salt.toByteArray(Charsets.UTF_8), 65536, 256)
                val tmp = factory.generateSecret(spec)
                val secretKey = SecretKeySpec(tmp.encoded, "AES")
                val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec)
                return String(cipher.doFinal(Base64.decode(ciphertext, Base64.DEFAULT)))
            } catch (e: Exception) {
                e.printStackTrace()
            }
            return null
        }
    }
}