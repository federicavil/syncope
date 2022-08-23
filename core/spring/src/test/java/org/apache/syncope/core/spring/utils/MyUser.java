package org.apache.syncope.core.spring.utils;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.entity.*;
import org.apache.syncope.core.persistence.api.entity.resource.ExternalResource;
import org.apache.syncope.core.persistence.api.entity.user.*;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public class MyUser implements User {

    private String status= "ACTIVE";
    private String username;
    private String password ;
    private CipherAlgorithm cipher = CipherAlgorithm.SHA256;
    private Integer failedlogins = 0;

    public MyUser(String username, String password){
        this.username = username;
        this.password = password;
    }

    public MyUser(){

    }

    @Override
    public OffsetDateTime getCreationDate() {
        return null;
    }

    @Override
    public String getCreator() {
        return null;
    }

    @Override
    public String getCreationContext() {
        return null;
    }

    @Override
    public OffsetDateTime getLastChangeDate() {
        return null;
    }

    @Override
    public String getLastModifier() {
        return null;
    }

    @Override
    public String getLastChangeContext() {
        return null;
    }

    @Override
    public void setCreationDate(OffsetDateTime creationDate) {

    }

    @Override
    public void setCreator(String creator) {

    }

    @Override
    public void setCreationContext(String context) {

    }

    @Override
    public void setLastChangeDate(OffsetDateTime lastChangeDate) {

    }

    @Override
    public void setLastModifier(String lastModifier) {

    }

    @Override
    public void setLastChangeContext(String context) {

    }

    @Override
    public AnyType getType() {
        return null;
    }

    @Override
    public void setType(AnyType type) {

    }

    @Override
    public Realm getRealm() {
        return null;
    }

    @Override
    public void setRealm(Realm realm) {

    }

    @Override
    public String getStatus() {
        return status;
    }

    @Override
    public void setStatus(String status) {
        this.status = status;
    }

    @Override
    public boolean add(ExternalResource resource) {
        return false;
    }

    @Override
    public List<? extends ExternalResource> getResources() {
        return null;
    }

    @Override
    public boolean add(AnyTypeClass auxClass) {
        return false;
    }

    @Override
    public List<? extends AnyTypeClass> getAuxClasses() {
        return null;
    }

    @Override
    public boolean add(UPlainAttr attr) {
        return false;
    }

    @Override
    public boolean remove(UPlainAttr attr) {
        return false;
    }

    @Override
    public Optional<? extends UPlainAttr> getPlainAttr(String plainSchema) {
        return Optional.empty();
    }

    @Override
    public List<? extends UPlainAttr> getPlainAttrs() {
        return null;
    }

    @Override
    public String getKey() {
        return null;
    }

    @Override
    public Optional<? extends UPlainAttr> getPlainAttr(String plainSchema, Membership<?> membership) {
        return Optional.empty();
    }

    @Override
    public Collection<? extends UPlainAttr> getPlainAttrs(String plainSchema) {
        return null;
    }

    @Override
    public Collection<? extends UPlainAttr> getPlainAttrs(Membership<?> membership) {
        return null;
    }

    @Override
    public boolean add(UMembership membership) {
        return false;
    }

    @Override
    public boolean remove(UMembership membership) {
        return false;
    }

    @Override
    public Optional<? extends UMembership> getMembership(String groupKey) {
        return Optional.empty();
    }

    @Override
    public List<? extends UMembership> getMemberships() {
        return null;
    }

    @Override
    public boolean add(URelationship relationship) {
        return false;
    }

    @Override
    public Optional<? extends URelationship> getRelationship(RelationshipType relationshipType, String otherEndKey) {
        return Optional.empty();
    }

    @Override
    public Collection<? extends URelationship> getRelationships(String otherEndKey) {
        return null;
    }

    @Override
    public Collection<? extends URelationship> getRelationships(RelationshipType relationshipType) {
        return null;
    }

    @Override
    public List<? extends URelationship> getRelationships() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public CipherAlgorithm getCipherAlgorithm() {
        return cipher;
    }

    @Override
    public boolean canDecodeSecrets() {
        return false;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public void setEncodedPassword(String password, CipherAlgorithm cipherAlgoritm) {

    }

    @Override
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public void setCipherAlgorithm(CipherAlgorithm cipherAlgorithm) {

    }

    @Override
    public Boolean isSuspended() {
        return status.equals("SUSPENDED");
    }

    @Override
    public void setSuspended(Boolean suspended) {
        this.status = "SUSPENDED";
    }

    @Override
    public String getToken() {
        return null;
    }

    @Override
    public OffsetDateTime getTokenExpireTime() {
        return null;
    }

    @Override
    public void generateToken(int tokenLength, int tokenExpireTime) {

    }

    @Override
    public void removeToken() {

    }

    @Override
    public boolean checkToken(String token) {
        return false;
    }

    @Override
    public boolean hasTokenExpired() {
        return false;
    }

    @Override
    public String getClearPassword() {
        return null;
    }

    @Override
    public void removeClearPassword() {

    }

    @Override
    public OffsetDateTime getChangePwdDate() {
        return null;
    }

    @Override
    public void setChangePwdDate(OffsetDateTime changePwdDate) {

    }

    @Override
    public List<String> getPasswordHistory() {
        return null;
    }

    @Override
    public SecurityQuestion getSecurityQuestion() {
        return null;
    }

    @Override
    public void setSecurityQuestion(SecurityQuestion securityQuestion) {

    }

    @Override
    public String getSecurityAnswer() {
        return null;
    }

    @Override
    public String getClearSecurityAnswer() {
        return null;
    }

    @Override
    public void setEncodedSecurityAnswer(String securityAnswer) {

    }

    @Override
    public void setSecurityAnswer(String securityAnswer) {

    }

    @Override
    public Integer getFailedLogins() {
        return this.failedlogins;
    }

    @Override
    public void setFailedLogins(Integer failedLogins) {
        this.failedlogins = failedLogins;
    }

    @Override
    public OffsetDateTime getLastLoginDate() {
        return null;
    }

    @Override
    public void setLastLoginDate(OffsetDateTime lastLoginDate) {

    }

    @Override
    public boolean isMustChangePassword() {
        return false;
    }

    @Override
    public void setMustChangePassword(boolean mustChangePassword) {

    }

    @Override
    public boolean add(Role role) {
        return false;
    }

    @Override
    public List<? extends Role> getRoles() {
        return null;
    }

    @Override
    public boolean add(LinkedAccount account) {
        return false;
    }

    @Override
    public Optional<? extends LinkedAccount> getLinkedAccount(String resource, String connObjectKeyValue) {
        return Optional.empty();
    }

    @Override
    public List<? extends LinkedAccount> getLinkedAccounts(String resource) {
        return null;
    }

    @Override
    public List<? extends LinkedAccount> getLinkedAccounts() {
        return null;
    }
}
