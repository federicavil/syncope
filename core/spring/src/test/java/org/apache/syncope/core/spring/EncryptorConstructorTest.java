package org.apache.syncope.core.spring;

import org.apache.syncope.core.spring.security.Encryptor;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class EncryptorConstructorTest {
    private String key;

    public EncryptorConstructorTest(String key){
        this.key = key;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        return Arrays.asList(new Object[][]{
                {null},
                {"123456789101112"},
                {"1234567891011121"},
                {"12345678910111213"}

        });
    }

    @Test
    public void constructorTest(){
        try {
            Encryptor instance = Encryptor.getInstance(this.key);
            Assert.assertNotNull(instance);
            Field specKeyField = Encryptor.class.getDeclaredField("keySpec");
            specKeyField.setAccessible(true);
            SecretKeySpec keySpec = (SecretKeySpec) specKeyField.get(instance);
            byte[] keyBytes = keySpec.getEncoded();
            Assert.assertEquals(16,keyBytes.length);
        } catch (IllegalArgumentException | NoSuchFieldException | IllegalAccessException e) {
            Assert.fail();
        }
    }

}
