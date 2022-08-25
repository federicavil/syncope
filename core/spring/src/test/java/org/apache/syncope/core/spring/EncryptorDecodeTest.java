package org.apache.syncope.core.spring;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.utils.EncryptorOracle;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class EncryptorDecodeTest extends EncryptorTest{

    private String encoded;
    private CipherAlgorithm cipher;
    private boolean isExceptionExpected;
    private String plainText;

    public EncryptorDecodeTest(EncodedType type, CipherAlgorithm cipher, boolean isExceptionExpected){
        configure(type, cipher, isExceptionExpected);

    }

    private void configure(EncodedType type, CipherAlgorithm cipher, boolean isExceptionExpected){
        this.cipher = cipher;
        this.isExceptionExpected = isExceptionExpected;
        String testEncoded = null;
        if(cipher == CipherAlgorithm.AES){
            if(type != EncodedType.NULL) {
                this.plainText = "test";
                testEncoded = EncryptorOracle.encode(plainText, cipher);
            }switch (type){
                case NULL:
                case RIGHTLEN:
                    this.encoded = testEncoded;
                    break;
                case MINORLEN:
                    this.encoded = testEncoded.substring(1);
                    break;
                case MAJORLEN:
                    this.encoded = testEncoded + "a";
                    break;
            }
        }
        else this.plainText = null;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        return Arrays.asList(new Object[][]{
                { EncodedType.NULL,      null,                     false},
                { EncodedType.NULL,      CipherAlgorithm.SHA,      false},
                { EncodedType.NULL,      CipherAlgorithm.SHA1,     false},
                { EncodedType.NULL,      CipherAlgorithm.SHA256,   false},
                { EncodedType.NULL,      CipherAlgorithm.SHA512,   false},
                { EncodedType.NULL,      CipherAlgorithm.SMD5,     false},
                { EncodedType.NULL,      CipherAlgorithm.BCRYPT,   false},
                { EncodedType.NULL,      CipherAlgorithm.SSHA,     false},
                { EncodedType.NULL,      CipherAlgorithm.SSHA1,    false},
                { EncodedType.NULL,      CipherAlgorithm.SSHA256,  false},
                { EncodedType.NULL,      CipherAlgorithm.SSHA512,  false},
                { EncodedType.NULL,      CipherAlgorithm.AES,      false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SHA,      false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SHA1,     false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SHA256,   false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SHA512,   false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SMD5,     false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.BCRYPT,   false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SSHA,     false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SSHA1,    false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SSHA256,  false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.SSHA512,  false},
                { EncodedType.RIGHTLEN,      CipherAlgorithm.AES,      false},
                { EncodedType.MINORLEN,      CipherAlgorithm.AES,      true},
                { EncodedType.MAJORLEN,      CipherAlgorithm.AES,      true},


        });
    }

    @Test
    public void encodeTest() {
        Exception e = null;
        try {
            String result = encryptor.decode(this.encoded,this.cipher);
            Assert.assertEquals(this.plainText,result);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | IllegalArgumentException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NullPointerException ex) {
            e = ex;
        }
        if(isExceptionExpected)
            Assert.assertNotNull(e);
        else{
            Assert.assertNull(e);
        }

    }

    public enum EncodedType{
        RIGHTLEN,
        MINORLEN,
        MAJORLEN,
        NULL
    }
}
