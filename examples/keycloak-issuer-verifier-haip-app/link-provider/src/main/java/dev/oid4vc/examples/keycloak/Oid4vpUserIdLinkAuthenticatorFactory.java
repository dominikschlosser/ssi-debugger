package dev.oid4vc.examples.keycloak;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public final class Oid4vpUserIdLinkAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "oid4vp-detect-user-by-id";
  private static final Oid4vpUserIdLinkAuthenticator SINGLETON =
      new Oid4vpUserIdLinkAuthenticator();

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return "oid4vpUserIdLink";
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.DISABLED
    };
  }

  @Override
  public String getDisplayType() {
    return "Detect existing broker user by credential user id";
  }

  @Override
  public String getHelpText() {
    return "Resolve the existing Keycloak user directly from the keycloak_user_id claim in the verified credential.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }
}
