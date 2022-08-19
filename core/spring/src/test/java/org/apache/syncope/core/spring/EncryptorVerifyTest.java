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
public class EncryptorVerifyTest extends EncryptorTest{
    private String value;
    private String encoded;
    private CipherAlgorithm cipher;
    private boolean isExceptionExpected;

    public EncryptorVerifyTest(String value, VerifyEncodedType encoded, CipherAlgorithm cipher, boolean isExceptionExpected){
        configure(value,encoded,cipher,isExceptionExpected);
    }

    private void configure(String value, VerifyEncodedType type, CipherAlgorithm cipher, boolean isExceptionExpected){
        this.cipher = cipher;
        this.value = value;
        this.isExceptionExpected = isExceptionExpected;

        switch(type){
            case NULL:
                this.encoded = null;
                break;
            case CORRESPONDING:
                this.encoded = EncryptorOracle.encode(this.value,this.cipher);
                break;
            case NOTCORRESPONDING:
                this.encoded = EncryptorOracle.encode("not "+ this.value, this.cipher);
                break;
        }
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        return Arrays.asList(new Object[][]{
                { null,      VerifyEncodedType.NULL,          null,                     true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SHA,      true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SHA1,     true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SHA256,   true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SHA512,   true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SMD5,     true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.BCRYPT,   true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SSHA,     true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SSHA1,    true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SSHA256,  true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.SSHA512,  true},
                { null,      VerifyEncodedType.NULL,          CipherAlgorithm.AES,      true},
                { "test",    VerifyEncodedType.NULL,          null,                     true},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SHA,      false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SHA1,     false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SHA256,   false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SHA512,   false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SMD5,     false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.BCRYPT,   false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SSHA,     false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SSHA1,    false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SSHA256,  false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.SSHA512,  false},
                { "test",    VerifyEncodedType.CORRESPONDING, CipherAlgorithm.AES,      false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SHA,      false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SHA1,     false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SHA256,   false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SHA512,   false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SMD5,     false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.BCRYPT,   false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SSHA,     false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SSHA1,    false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SSHA256,  false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.SSHA512,  false},
                { "test",    VerifyEncodedType.NOTCORRESPONDING, CipherAlgorithm.AES,      false},

        });
    }

    @Test
    public void verifyTest(){
        Exception e = null;
        try {
            boolean result = encryptor.verify(this.value, this.cipher, this.encoded);
            boolean expected = EncryptorOracle.verify(this.value, this.encoded, this.cipher);
            Assert.assertEquals(expected, result);
        }catch(Exception ex){
            e = ex;
        if(isExceptionExpected)
            Assert.assertNotNull(e);
        else{
            Assert.assertNull(e);
        }

    }
    }

    public enum VerifyEncodedType{
        NULL,
        CORRESPONDING,
        NOTCORRESPONDING
    }
}
