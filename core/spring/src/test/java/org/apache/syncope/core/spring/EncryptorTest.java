package org.apache.syncope.core.spring;

import org.apache.syncope.core.spring.security.Encryptor;
import org.apache.syncope.core.spring.security.SecurityProperties;
import org.apache.syncope.core.spring.utils.EncryptorOracle;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.context.ConfigurableApplicationContext;

import static org.mockito.Mockito.when;

public class EncryptorTest {

    protected static Encryptor encryptor;
    private static MockedStatic<ApplicationContextProvider> provider;

    @BeforeClass
    public static void setUp(){
        encryptor = Encryptor.getInstance(EncryptorOracle.getKey());
        SecurityProperties securityProperties = new SecurityProperties();
        ConfigurableApplicationContext ctx = Mockito.mock(ConfigurableApplicationContext.class);
        when(ctx.getBean(SecurityProperties.class)).thenReturn(securityProperties);
        provider = Mockito.mockStatic(ApplicationContextProvider.class);
        provider.when(ApplicationContextProvider::getApplicationContext).thenReturn(ctx);
        securityProperties.getDigester().setSaltSizeBytes(0);

    }

    @AfterClass
    public static void closeCtxProvider() {
        if (provider != null)
            provider.close();
    }
}
