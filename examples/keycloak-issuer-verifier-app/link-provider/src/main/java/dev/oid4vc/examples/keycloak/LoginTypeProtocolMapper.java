package dev.oid4vc.examples.keycloak;

import java.util.Collections;
import java.util.List;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

public final class LoginTypeProtocolMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper {
  public static final String PROVIDER_ID = "oid4vc-login-type-protocol-mapper";
  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = Collections.emptyList();
  private static final String CLAIM_NAME = "login_type";
  private static final String BASIC_LOGIN = "basic";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Demo Login Type";
  }

  @Override
  public String getDisplayCategory() {
    return TOKEN_MAPPER_CATEGORY;
  }

  @Override
  public String getHelpText() {
    return "Adds login_type=basic for local logins and login_type=wallet for brokered OID4VP logins.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
    token.getOtherClaims().put(CLAIM_NAME, resolveLoginType(userSession));
  }

  private String resolveLoginType(UserSessionModel userSession) {
    if (userSession != null) {
      String loginType = userSession.getNote(CLAIM_NAME);
      if (loginType != null && !loginType.isBlank()) {
        return loginType;
      }
    }
    return BASIC_LOGIN;
  }
}
