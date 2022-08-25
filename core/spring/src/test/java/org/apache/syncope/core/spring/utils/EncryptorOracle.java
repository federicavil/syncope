package org.apache.syncope.core.spring.utils;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.google.common.hash.Hashing;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.syncope.common.lib.types.CipherAlgorithm;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class EncryptorOracle {

    private static final String key = "dfe0855edfmsh485";

    public static boolean verify(String plainText, String cipherText, CipherAlgorithm cipher){
        return verify(plainText,cipherText,cipher,key);
    }

    public static boolean verify(String plainText, String cipherText, CipherAlgorithm cipher, String key){
        switch(cipher){
            case BCRYPT:
                return BCrypt.verifyer().verify(plainText.toCharArray(), cipherText).verified;
            default:
                return encode(plainText,cipher,key).equalsIgnoreCase(cipherText);
        }
    }
    public static String encode(String plainText, CipherAlgorithm cipher){
        return encode(plainText,cipher,key);
    }

    public static String encode(String plainText, CipherAlgorithm cipher,String key){
        String encryptedString = null;
        switch(cipher){
            case SMD5:
                encryptedString = Hashing.md5().hashString(plainText, StandardCharsets.UTF_8).toString();
                break;
            case SHA:
            case SHA1:
            case SSHA:
            case SSHA1:
                encryptedString = Hashing.sha1().hashString(plainText, StandardCharsets.UTF_8).toString();
                break;
            case SSHA256:
            case SHA256:
                encryptedString = Hashing.sha256().hashString(plainText, StandardCharsets.UTF_8).toString();
                break;
            case SSHA512:
            case SHA512:
                encryptedString = Hashing.sha512().hashString(plainText, StandardCharsets.UTF_8).toString();
                break;
            case BCRYPT:
                encryptedString = BCrypt.withDefaults().hashToString(10, plainText.toCharArray());
                break;
            case AES:
                try {
                    Cipher ciph = Cipher.getInstance("AES");
                    SecretKeySpec speckey = new SecretKeySpec(ArrayUtils.subarray(
                            getKey().getBytes(StandardCharsets.UTF_8), 0, 16),
                            CipherAlgorithm.AES.getAlgorithm());
                    ciph.init(Cipher.ENCRYPT_MODE,speckey);
                    encryptedString = Base64.getEncoder()
                            .encodeToString(ciph.doFinal(plainText.getBytes(StandardCharsets.UTF_8)));
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }
                break;

        }
        return encryptedString;
    }

    public static String getKey(){
        return key;
    }


}
