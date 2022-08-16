package org.apache.syncope.core.spring.utils;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.google.common.hash.Hashing;
import org.apache.syncope.common.lib.types.CipherAlgorithm;

import java.nio.charset.StandardCharsets;

public class EncryptorOracle {

    private static final String key = "dfe0855edfmsh485836b5158bba7p10f2ddjsn68761a02af10";

    public static boolean verify(String plainText, String cipherText, CipherAlgorithm cipher){
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
                return BCrypt.verifyer().verify(plainText.toCharArray(), cipherText).verified;
            case AES:
                //TODO

        }
        return encryptedString.equalsIgnoreCase(cipherText);
    }



    public static String getKey(){
        return key;
    }

}
