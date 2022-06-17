package com.rnfingerprint;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.RequiresApi;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Helper to create a Cipher.
 */
@TargetApi(Build.VERSION_CODES.M)
public class FingerprintCipher {

    private static final String KEY_NAME = "example_key";
    private static final String CIPHER_ALGO = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private Cipher cipher;
    private String token;
    public Cipher getCipher() {
        try {
            cipher = Cipher.getInstance(CIPHER_ALGO);
            KeyPair keyPair = getKeyPair();
            if (keyPair == null) {
                keyPair = genKeyPair();
            }

            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            token = Base64.encodeToString(keyPair.getPublic().getEncoded(), 2);

        } catch (KeyPermanentlyInvalidatedException ex) {
            try {
                genKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return getCipher();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return cipher;
    }

    public String getToken() {
        return token;
    }

    private KeyPair genKeyPair() throws Exception {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)

                .setUserAuthenticationRequired(true);
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true);
        }
        return generateKeyPair(builder.build());
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private KeyPair generateKeyPair(KeyGenParameterSpec keyGenParameterSpec) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        keyPairGenerator.initialize(keyGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair getKeyPair() throws Exception {
        // Before the keystore can be accessed, it must be loaded.
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Key key = keyStore.getKey(KEY_NAME, null);
        if (key instanceof PrivateKey && keyStore.getCertificate(KEY_NAME) != null) {
            // Get certificate of public key
            Certificate cert = keyStore.getCertificate(KEY_NAME);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            return new KeyPair(publicKey, (PrivateKey) key);
        }
        return null;
    }
}
