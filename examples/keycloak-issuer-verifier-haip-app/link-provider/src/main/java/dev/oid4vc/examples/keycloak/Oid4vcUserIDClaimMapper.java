package dev.oid4vc.examples.keycloak;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCMapper;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;

public final class Oid4vcUserIDClaimMapper extends OID4VCMapper {
  public static final String PROVIDER_ID = "oid4vc-user-id-claim-mapper";
  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = Collections.emptyList();
  private static final String CLAIM_NAME = "keycloak_user_id";

  @Override
  protected List<ProviderConfigProperty> getIndividualConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  public void setClaim(VerifiableCredential verifiableCredential, UserSessionModel userSessionModel) {}

  @Override
  public void setClaim(Map<String, Object> claims, UserSessionModel userSessionModel) {
    if (userSessionModel == null || userSessionModel.getUser() == null) {
      return;
    }
    claims.put(CLAIM_NAME, userSessionModel.getUser().getId());
  }

  @Override
  public String getDisplayType() {
    return "Demo User ID Claim";
  }

  @Override
  public String getHelpText() {
    return "Adds keycloak_user_id from the internal Keycloak user ID.";
  }

  @Override
  public ProtocolMapper create(KeycloakSession session) {
    return new Oid4vcUserIDClaimMapper();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
