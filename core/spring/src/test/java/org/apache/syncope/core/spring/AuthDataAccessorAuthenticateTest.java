package org.apache.syncope.core.spring;

import org.apache.commons.lang3.tuple.Triple;
import org.apache.syncope.common.keymaster.client.api.ConfParamOps;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.ImplementationLookup;
import org.apache.syncope.core.persistence.api.dao.*;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.provisioning.api.AuditManager;
import org.apache.syncope.core.provisioning.api.ConnectorManager;
import org.apache.syncope.core.provisioning.api.MappingManager;
import org.apache.syncope.core.spring.security.*;
import org.apache.syncope.core.spring.utils.EncryptorOracle;
import org.apache.syncope.core.spring.utils.MyUser;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;

@RunWith(Parameterized.class)
public class AuthDataAccessorAuthenticateTest {
    @Spy
    private SecurityProperties securityProperties;
    @Mock
    private RealmDAO realmDAO;
    @Mock
    private UserDAO userDAO;
    @Mock
    private GroupDAO groupDAO;
    @Mock
    private AnyTypeDAO anyTypeDAO;
    @Mock
    private AnySearchDAO anySearchDAO;
    @Mock
    private AccessTokenDAO accessTokenDAO;

    private ConfParamOps confParamOps;
    @Mock
    private RoleDAO roleDAO;
    @Mock
    private DelegationDAO delegationDAO;
    @Mock
    private ConnectorManager connectorManager;
    @Mock
    private AuditManager auditManager;
    @Mock
    private MappingManager mappingManager;
    @Mock
    private ImplementationLookup implementationLookup;

    private Map<String, JWTSSOProvider> jwtSSOProviders;
    private AuthDataAccessor authDataAccessor;

    private UsernamePasswordAuthenticationProvider provider;

    private String domain;
    private Authentication auth;
    private boolean isExceptionExpected;
    private String username;
    private String password;
    private User userResult;
    private Boolean authenticationResult;

    public AuthDataAccessorAuthenticateTest(String domain, UserType type, boolean isExceptionExpected){
        configure(domain,type,isExceptionExpected);
    }

    private void configure(String domain, UserType type, boolean isExceptionExpected){
        this.domain = domain;
        this.isExceptionExpected = isExceptionExpected;
        username = "myUsername";
        password = "myPassword";
        userDAO = Mockito.mock(UserDAO.class);
        User user = null;
        switch(type){
            case NULL:
                auth = null;
                break;
            case ACTIVEANDCORRECT:
                user = new MyUser(username, EncryptorOracle.encode(password, CipherAlgorithm.SHA256));
                authenticationResult = true;
                Mockito.when(userDAO.findByUsername(any())).thenReturn(user);
                break;
            case ACTIVEANDWRONG:
                user = new MyUser(username, EncryptorOracle.encode("wrongpassword", CipherAlgorithm.SHA256));
                authenticationResult = false;
                Mockito.when(userDAO.findByUsername(any())).thenReturn(user);
                break;
            case SUSPENDED:
                user = new MyUser(username, EncryptorOracle.encode(password, CipherAlgorithm.SHA256));
                user.setStatus("SUSPENDED");
                authenticationResult = false;
                Mockito.when(userDAO.findByUsername(any())).thenReturn(user);
                break;
            case NOTEXISTENT:
                authenticationResult = null;
                Mockito.when(userDAO.findByUsername(any())).thenReturn(null);
                break;

        }
        userResult = user;
        // Mock ConfParamOps
        confParamOps = Mockito.mock(ConfParamOps.class);
        Mockito.when(confParamOps.get(anyString(),eq("authentication.attributes"),any(),any())).thenReturn(new String[]{"username"});
        Mockito.when(confParamOps.get(any(),eq("authentication.statuses"),any(),any())).thenReturn(new String[]{"ACTIVE"});
        Mockito.when(confParamOps.get(any(),eq("log.lastlogindate"),any(),any())).thenReturn(true);
        // Mock authentication
        auth = Mockito.mock(Authentication.class);
        Mockito.when(auth.getName()).thenReturn(username);
        Mockito.when(auth.getCredentials()).thenReturn(password);
        Mockito.when(auth.getDetails()).thenReturn(new SyncopeAuthenticationDetails(domain,null));
        // Mock RealmDAO
        realmDAO = Mockito.mock(RealmDAO.class);
        Realm mockRealm = Mockito.mock(Realm.class);
        Mockito.when(realmDAO.findAncestors(any())).thenReturn(Arrays.asList(mockRealm));
        this.authDataAccessor = new AuthDataAccessor(new SecurityProperties(),realmDAO,userDAO,null,null,null,null,confParamOps,null,null,null,null,null,null);
    }

    @Parameterized.Parameters
    public static Collection<Object[]> getTestParameters() {
        return Arrays.asList(new Object[][]{
                {null,      UserType.NULL,              true},
                {null,      UserType.ACTIVEANDCORRECT,  true},
                {"Master",  UserType.NULL,              false},
                {"Master",  UserType.NOTEXISTENT,       false},
                {"Master",  UserType.ACTIVEANDCORRECT,  false},
                {"Master",  UserType.ACTIVEANDWRONG,    false},
                {"Master",  UserType.SUSPENDED,         true},
                {"Domain1",  UserType.NULL,              false},
                {"Domain1",  UserType.NOTEXISTENT,       false},
                {"Domain1",  UserType.ACTIVEANDCORRECT,  false},
                {"Domain1",  UserType.ACTIVEANDWRONG,    false},
                {"Domain1",  UserType.SUSPENDED,         true},
        });
    }

    @Test
    public void authenticateTest(){
        Exception e = null;
        try{
            Triple<User, Boolean, String> result = authDataAccessor.authenticate(domain,auth);

            Assert.assertEquals(userResult,result.getLeft());
            Assert.assertEquals(authenticationResult,result.getMiddle());
        }catch(NullPointerException | DisabledException ex){
            e = ex;
        }
        if(isExceptionExpected)
            Assert.assertNotNull(e);
        else
            Assert.assertNull(e);
    }


    public enum UserType{
        NULL,
        ACTIVEANDCORRECT,
        ACTIVEANDWRONG,
        SUSPENDED,
        NOTEXISTENT
    }
}
