package com.yslvlln.encryptionlib

import android.os.Build
import android.util.Base64
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class Encrypt {
    companion object {
        fun encrypt(plaintext: String, secretkey: String, salt: String): String? {
            var factory: SecretKeyFactory? =  null
            try {
                val iv = ByteArray(16)
                val ivSpec = IvParameterSpec(iv)
                //PBKDF2WithHmacSHA256 is not supported before API 26.
                //PBKDF2 is the key derivation suggested by google.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                } else {
                    factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
                }
                //Specifications how the key should be generated
                val spec: KeySpec = PBEKeySpec(secretkey.toCharArray(), salt.toByteArray(Charsets.UTF_8), 65536, 256)
                //Generate secret key
                val tmp: SecretKey = factory.generateSecret(spec)
                val secretKey = SecretKeySpec(tmp.getEncoded(), "AES")
                //Set transformation
                //PKCS5Padding only means each block is strictly 8 bytes
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
                return Base64.encodeToString(cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8)), Base64.DEFAULT)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            return null
        }
    }
}