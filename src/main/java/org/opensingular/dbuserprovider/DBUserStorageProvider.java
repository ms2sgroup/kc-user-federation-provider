package org.opensingular.dbuserprovider;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;
import org.opensingular.dbuserprovider.model.QueryConfigurations;
import org.opensingular.dbuserprovider.model.UserAdapter;
import org.opensingular.dbuserprovider.persistence.DataSourceProvider;
import org.opensingular.dbuserprovider.persistence.UserRepository;
import org.opensingular.dbuserprovider.util.PagingUtil;

import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class DBUserStorageProvider implements UserStorageProvider,
                                              UserLookupProvider, UserQueryProvider, CredentialInputUpdater, CredentialInputValidator, UserRegistrationProvider {
    
    private final KeycloakSession session;
    private final ComponentModel  model;
    private final UserRepository  repository;
    private final boolean allowDatabaseToOverwriteKeycloak;
    
    private final String role_teacher = "TEACHER";
    private final String role_professional = "PROFESSIONAL";
    private final String role_admin = "ADMIN";
    private final String role_parent="PARENT";
    private final String role_center_admin="CENTER_ADMIN";
    
    private final String client = "client-atenxia";

    DBUserStorageProvider(KeycloakSession session, ComponentModel model, DataSourceProvider dataSourceProvider, QueryConfigurations queryConfigurations) {
        this.session    = session;
        this.model      = model;
        this.repository = new UserRepository(dataSourceProvider, queryConfigurations);
        this.allowDatabaseToOverwriteKeycloak = queryConfigurations.getAllowDatabaseToOverwriteKeycloak();
    }
    
    
    private List<UserModel> toUserModel(RealmModel realm, List<Map<String, String>> users) {
        return users.stream()
                    .map(m -> new UserAdapter(session, realm, model, m, allowDatabaseToOverwriteKeycloak)).collect(Collectors.toList());
    }
    
    
    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }
    
    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }
    
    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        
        log.infov("isValid user credential: userId={0}", user.getId());
        System.out.println("Entra a isValid realm: "+realm.getName()+", userModel: "+user.getEmail()+" user id: "+user.getId()+" input: "+input.getType());
        
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
            return false;
        }
        
        UserCredentialModel cred = (UserCredentialModel) input;

        UserModel dbUser = user;
        // If the cache just got loaded in the last 500 millisec (i.e. probably part of the actual flow), there is no point in reloading the user.)
        if (allowDatabaseToOverwriteKeycloak && user instanceof CachedUserModel && (System.currentTimeMillis() - ((CachedUserModel) user).getCacheTimestamp()) > 500) {
          dbUser = this.getUserById(user.getId(), realm);

          if (dbUser == null) {
            ((CachedUserModel) user).invalidate();
            return false;
          }

          // For now, we'll just invalidate the cache if username or email has changed. Eventually we could check all (or a parametered list of) attributes fetched from the DB.
          if (!java.util.Objects.equals(user.getUsername(), dbUser.getUsername()) || !java.util.Objects.equals(user.getEmail(), dbUser.getEmail())) {
            ((CachedUserModel) user).invalidate();
          }
        }
        return repository.validateCredentials(dbUser.getUsername(), cred.getChallengeResponse());
    }
    
    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        
        log.infov("updating credential: realm={0} user={1}", realm.getId(), user.getUsername());
        
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
            return false;
        }
        
        UserCredentialModel cred = (UserCredentialModel) input;
        return repository.updateCredentials(user.getUsername(), cred.getChallengeResponse());
    }
    
    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
    }
    
    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.emptySet();
    }
    
    @Override
    public void preRemove(RealmModel realm) {
        
        log.infov("pre-remove realm");
    }
    
    @Override
    public void preRemove(RealmModel realm, GroupModel group) {
        
        log.infov("pre-remove group");
    }
    
    @Override
    public void preRemove(RealmModel realm, RoleModel role) {
        
        log.infov("pre-remove role");
    }
    
    @Override
    public void close() {
        log.debugv("closing");
    }
    
    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        
        log.infov("lookup user by id: realm={0} userId={1}", realm.getId(), id);
        
        String externalId = StorageId.externalId(id);
        Map<String, String> user = repository.findUserById(externalId);

        if (user == null) {
            log.debugv("findUserById returned null, skipping creation of UserAdapter, expect login error");
            return null;
        } else {
            return new UserAdapter(session, realm, model, user, allowDatabaseToOverwriteKeycloak);
        }
    }
    
    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        
        log.infov("lookup user by username: realm={0} username={1}", realm.getId(), username);
        UserModel user = repository.findUserByUsername(username).map(u -> new UserAdapter(session, realm, model, u, allowDatabaseToOverwriteKeycloak)).orElse(null);
        	
        Map<String, String> roles = repository.findRolesByUser(username); 
        if(!roles.isEmpty())
        {
            boolean center_admin = (roles.get("is_center_admin").equals("t")) ? true:false;
            boolean parent = (roles.get("is_parent").equals("t")) ? true:false;
            boolean professional = (roles.get("is_professional").equals("t")) ? true:false;
            boolean teacher = (roles.get("is_teacher").equals("t")) ? true:false;
            boolean admin = (roles.get("is_staff").equals("t")) ? true:false;
            
            log.infov("lookup user by username roles " + center_admin +"," +parent+"," +professional+"," +teacher+"," +admin);
            
            if (teacher)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_teacher));
            if (parent)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_parent));
            if (professional)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_professional));
            if (center_admin)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_center_admin));
            if (admin)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_admin));
        }
        
        return user;
    }
    
    private RoleModel getRoleFromString(RealmModel realm, String clientId, String roleName) {
	log.infov("getRoleFromString " + roleName);
	RoleModel role = null;
        ClientModel client = realm.getClientByClientId(clientId);
        if (client != null) {
        	try
                {
        	    role = client.getRole(roleName);
                }
                catch(Exception e)
                {
            	
                }
        }
        
        return role;
    }
    
    // Used for hardcoded role mappers
    /*private String[] parseRole(String role) {
        int scopeIndex = role.lastIndexOf('.');
        if (scopeIndex > -1) {
            String appName = role.substring(0, scopeIndex);
            role = role.substring(scopeIndex + 1);
            String[] rtn = {appName, role};
            return rtn;
        } else {
            String[] rtn = {null, role};
            return rtn;

        }
    }*/
    
    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        
        log.infov("lookup user by username: realm={0} email={1}", realm.getId(), email);
        
        return getUserByUsername(email, realm);
    }
    
    @Override
    public int getUsersCount(RealmModel realm) {
        return repository.getUsersCount(null);
    }
    
    @Override
    public int getUsersCount(RealmModel realm, Set<String> groupIds) {
        return repository.getUsersCount(null);
    }
    
    @Override
    public int getUsersCount(RealmModel realm, String search) {
        return repository.getUsersCount(search);
    }
    
    @Override
    public int getUsersCount(RealmModel realm, String search, Set<String> groupIds) {
        return repository.getUsersCount(search);
    }
    
    @Override
    public int getUsersCount(RealmModel realm, Map<String, String> params) {
        return repository.getUsersCount(null);
    }
    
    @Override
    public int getUsersCount(RealmModel realm, Map<String, String> params, Set<String> groupIds) {
        return repository.getUsersCount(null);
    }
    
    @Override
    public int getUsersCount(RealmModel realm, boolean includeServiceAccount) {
        return repository.getUsersCount(null);
    }
    
    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        log.infov("list users: realm={0}", realm.getId());
        return internalSearchForUser(null, realm, null);
    }
    
    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        
        log.infov("list users: realm={0} firstResult={1} maxResults={2}", realm.getId(), firstResult, maxResults);
        return internalSearchForUser(null, realm, new PagingUtil.Pageable(firstResult, maxResults));
    }
    
    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        log.infov("search for users: realm={0} search={1}", realm.getId(), search);
        return internalSearchForUser(search, realm, null);
    }
    
    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        log.infov("search for users: realm={0} search={1} firstResult={2} maxResults={3}", realm.getId(), search, firstResult, maxResults);
        return internalSearchForUser(search, realm, new PagingUtil.Pageable(firstResult, maxResults));
    }
    
    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        log.infov("search for users with params: realm={0} params={1}", realm.getId(), params);
        return internalSearchForUser(params.values().stream().findFirst().orElse(null), realm, null);
    }
    
    private List<UserModel> internalSearchForUser(String search, RealmModel realm, PagingUtil.Pageable pageable) {
        return toUserModel(realm, repository.findUsers(search, pageable));
    }
    
    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        log.infov("search for users with params: realm={0} params={1} firstResult={2} maxResults={3}", realm.getId(), params, firstResult, maxResults);
        return internalSearchForUser(params.values().stream().findFirst().orElse(null), realm, new PagingUtil.Pageable(firstResult, maxResults));
    }
    
    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        log.infov("search for group members with params: realm={0} groupId={1} firstResult={2} maxResults={3}", realm.getId(), group.getId(), firstResult, maxResults);
        return Collections.emptyList();
    }
    
    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        log.infov("search for group members: realm={0} groupId={1} firstResult={2} maxResults={3}", realm.getId(), group.getId());
        return Collections.emptyList();
    }
    
    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        log.infov("search for group members: realm={0} attrName={1} attrValue={2}", realm.getId(), attrName, attrValue);
        return Collections.emptyList();
    }
    
    
    @Override
    public UserModel addUser(RealmModel realm, String username) {
        // from documentation: "If your provider has a configuration switch to turn off adding a user, returning null from this method will skip the provider and call the next one."
        return null;
    }
    
    
    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        boolean userRemoved = repository.removeUser();
        
        if (userRemoved) {
            log.infov("deleted keycloak user: realm={0} userId={1} username={2}", realm.getId(), user.getId(), user.getUsername());
        }
        
        return userRemoved;
    }
    
    
    /**
     * Searches for users whose username, email, first name or last name contain any of the strings in {@code search} separated by whitespace.
     * <p/>
     * If possible, implementations should treat the parameter values as partial match patterns (i.e. in RDMBS terms use LIKE).
     * <p/>
     * This method is used by the admin console search box
     *
     * @param realm a reference to the realm.
     * @param search case insensitive list of string separated by whitespaces.
     * @param firstResult first result to return. Ignored if negative, zero, or {@code null}.
     * @param maxResults maximum number of results to return. Ignored if negative or {@code null}.
     * @return a non-null {@link Stream} of users that match the search criteria.
     */
    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
        List<UserModel> value = this.searchForUser(search, realm, firstResult == null ? -1 : firstResult, maxResults == null ? -1 : maxResults);
        return value != null ? value.stream() : Stream.empty();
    }
    
    /**
     * Searches for user by parameter. If possible, implementations should treat the parameter values as partial match patterns
     * (i.e. in RDMBS terms use LIKE).
     * <p/>
     * Valid parameters are:
     * <ul>
     *     <li>{@link UserModel#FIRST_NAME} - first name (case insensitive string)</li>
     *     <li>{@link UserModel#LAST_NAME} - last name (case insensitive string)</li>
     *     <li>{@link UserModel#EMAIL} - email (case insensitive string)</li>
     *     <li>{@link UserModel#USERNAME} - username (case insensitive string)</li>
     *     <li>{@link UserModel#EMAIL_VERIFIED} - search only for users with verified/non-verified email (true/false)</li>
     *     <li>{@link UserModel#ENABLED} - search only for enabled/disabled users (true/false)</li>
     *     <li>{@link UserModel#IDP_ALIAS} - search only for users that have a federated identity
     *     from idp with the given alias configured (case sensitive string)</li>
     *     <li>{@link UserModel#IDP_USER_ID} - search for users with federated identity with
     *     the given userId (case sensitive string)</li>
     * </ul>
     *
     * Any other parameters will be treated as custom user attributes.
     *
     * This method is used by the REST API when querying users.
     *
     * @param realm a reference to the realm.
     * @param params a map containing the search parameters.
     * @param firstResult first result to return. Ignored if negative, zero, or {@code null}.
     * @param maxResults maximum number of results to return. Ignored if negative or {@code null}.
     * @return a non-null {@link Stream} of users that match the search criteria.
     */
    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        List<UserModel> value = this.searchForUser(params, realm, firstResult == null ? -1 : firstResult, maxResults == null ? -1 : maxResults);
        return value != null ? value.stream() : Stream.empty();
    }
    
    /**
     * Returns a user with the given username belonging to the realm
     *
     * @param username case insensitive username (case-sensitivity is controlled by storage)
     * @param realm the realm model
     * @return found user model, or {@code null} if no such user exists
     */
    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        return getUserByUsername(username, realm);
    }
    
    /**
     * Returns a user with the given id belonging to the realm
     *
     * @param id id of the user
     * @param realm the realm model
     * @return found user model, or {@code null} if no such user exists
     */
    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        return getUserById(id, realm);
    }
    
    /**
     * Obtains the set of credential types that can be disabled via {@link #disableCredentialType(RealmModel, UserModel, String)
     * disableCredentialType}.
     *
     * @param realm a reference to the realm.
     * @param user the user whose credentials are being searched.
     * @return a non-null {@link Stream} of credential types.
     */
    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        Set<String> result = this.getDisableableCredentialTypes(realm, user);
        return result != null ? result.stream() : Stream.empty();
    }
}
