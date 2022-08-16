package org.apache.syncope.core.spring;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.security.Encryptor;
import org.apache.syncope.core.spring.security.SecurityProperties;
import org.apache.syncope.core.spring.utils.EncryptorOracle;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.context.ConfigurableApplicationContext;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class EncryptorTest {

    private static Encryptor encryptor;
    private String value;
    private CipherAlgorithm cipher;
    private boolean isExceptionExpected;

    public EncryptorTest(String value, CipherAlgorithm cipher, boolean isExceptionExpected){
        configure(value,cipher,isExceptionExpected);
    }

    private void configure(String value, CipherAlgorithm cipher, boolean isExceptionExpected){
        this.value = value;
        this.cipher = cipher;
        this.isExceptionExpected = isExceptionExpected;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        return Arrays.asList(new Object[][]{
                { null,      null,                     true},
                { null,      CipherAlgorithm.SHA,      true},
                { null,      CipherAlgorithm.SHA1,     true},
                { null,      CipherAlgorithm.SHA256,   true},
                { null,      CipherAlgorithm.SHA512,   true},
                { null,      CipherAlgorithm.SMD5,     true},
                { null,      CipherAlgorithm.BCRYPT,   true},
                { null,      CipherAlgorithm.SSHA,     true},
                { null,      CipherAlgorithm.SSHA1,    true},
                { null,      CipherAlgorithm.SSHA256,  true},
                { null,      CipherAlgorithm.SSHA512,  true},
                //{ null,      CipherAlgorithm.AES,      true},
                { "",      null,                     true},
                { "",      CipherAlgorithm.SHA,      false},
                { "",      CipherAlgorithm.SHA1,     false},
                { "",      CipherAlgorithm.SHA256,   false},
                { "",      CipherAlgorithm.SHA512,   false},
                { "",      CipherAlgorithm.SMD5,     false},
                { "",      CipherAlgorithm.BCRYPT,   false},
                { "",      CipherAlgorithm.SSHA,     false},
                { "",      CipherAlgorithm.SSHA1,    false},
                { "",      CipherAlgorithm.SSHA256,  false},
                { "",      CipherAlgorithm.SSHA512,  false},
                //{ "",      CipherAlgorithm.AES,      false},
                { "test",      null,                     true},
                { "test",      CipherAlgorithm.SHA,      false},
                { "test",      CipherAlgorithm.SHA1,     false},
                { "test",      CipherAlgorithm.SHA256,   false},
                { "test",      CipherAlgorithm.SHA512,   false},
                { "test",      CipherAlgorithm.SMD5,     false},
                { "test",      CipherAlgorithm.BCRYPT,   false},
                { "test",      CipherAlgorithm.SSHA,     false},
                { "test",      CipherAlgorithm.SSHA1,    false},
                { "test",      CipherAlgorithm.SSHA256,  false},
                { "test",      CipherAlgorithm.SSHA512,  false},
                //{ "test",      CipherAlgorithm.AES,      false},

        });
    }


    @BeforeClass
    public static void setUp(){
        encryptor = Encryptor.getInstance();
        SecurityProperties securityProperties = new SecurityProperties();
        ConfigurableApplicationContext ctx = Mockito.mock(ConfigurableApplicationContext.class);
        when(ctx.getBean(SecurityProperties.class)).thenReturn(securityProperties);
        MockedStatic<ApplicationContextProvider> provider = Mockito.mockStatic(ApplicationContextProvider.class);
        provider.when(ApplicationContextProvider::getApplicationContext).thenReturn(ctx);
        securityProperties.getDigester().setSaltSizeBytes(0);

    }

    @Test
    public void encodeTest() throws IOException, InterruptedException {
        Exception e = null;
        try {
            String result = encryptor.encode(this.value,this.cipher);
            boolean verify = EncryptorOracle.verify(this.value,result,this.cipher);
            Assert.assertTrue(verify);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NullPointerException ex) {
            e = ex;
        }
        if(isExceptionExpected)
            Assert.assertNotNull(e);
        else{
            Assert.assertNull(e);
        }


    }
}
