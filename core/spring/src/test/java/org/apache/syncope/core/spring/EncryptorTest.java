package org.apache.syncope.core.spring;

import org.apache.syncope.core.spring.security.Encryptor;
import org.apache.syncope.core.spring.security.SecurityProperties;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.context.ConfigurableApplicationContext;

import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class EncryptorTest {

    protected static Encryptor encryptor;

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


}
