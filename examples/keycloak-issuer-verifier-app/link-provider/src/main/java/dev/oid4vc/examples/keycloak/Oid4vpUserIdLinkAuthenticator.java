package dev.oid4vc.examples.keycloak;

import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

public final class Oid4vpUserIdLinkAuthenticator extends AbstractIdpAuthenticator {
  static final String CLAIM_NAME = "keycloak_user_id";
  private static final Logger LOG = Logger.getLogger(Oid4vpUserIdLinkAuthenticator.class);

  @Override
  protected void authenticateImpl(
      AuthenticationFlowContext context,
      SerializedBrokeredIdentityContext serializedContext,
      BrokeredIdentityContext brokerContext) {
    if (context.getAuthenticationSession().getAuthNote(EXISTING_USER_INFO) != null) {
      context.attempted();
      return;
    }

    String keycloakUserID = resolveUserID(brokerContext);
    if (StringUtil.isBlank(keycloakUserID)) {
      sendFailureChallenge(
          context,
          Response.Status.BAD_REQUEST,
          "missing_keycloak_user_id_claim",
          "identityProviderUnexpectedErrorMessage",
          AuthenticationFlowError.IDENTITY_PROVIDER_ERROR);
      return;
    }

    UserModel user = context.getSession().users().getUserById(context.getRealm(), keycloakUserID);
    if (user == null) {
      LOG.errorf(
          "No Keycloak user found for brokered credential claim %s=%s",
          CLAIM_NAME,
          keycloakUserID);
      sendFailureChallenge(
          context,
          Response.Status.UNAUTHORIZED,
          "keycloak_user_not_found_for_credential",
          "identityProviderUnexpectedErrorMessage",
          AuthenticationFlowError.INVALID_USER);
      return;
    }

    LOG.debugf(
        "Resolved brokered wallet login to existing Keycloak user '%s' via claim %s",
        user.getId(),
        CLAIM_NAME);
    ExistingUserInfo existingUser = new ExistingUserInfo(user.getId(), "id", user.getId());
    context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, existingUser.serialize());
    context.success();
  }

  @Override
  protected void actionImpl(
      AuthenticationFlowContext context,
      SerializedBrokeredIdentityContext serializedContext,
      BrokeredIdentityContext brokerContext) {
    authenticateImpl(context, serializedContext, brokerContext);
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(
      org.keycloak.models.KeycloakSession session,
      org.keycloak.models.RealmModel realm,
      UserModel user) {
    return true;
  }

  private String resolveUserID(BrokeredIdentityContext brokerContext) {
    Object claims = brokerContext.getContextData().get("oid4vp_claims");
    if (!(claims instanceof Map<?, ?> claimMap)) {
      return null;
    }
    Object claimValue = getNestedValue(claimMap, CLAIM_NAME);
    if (claimValue == null) {
      return null;
    }
    String stringValue = claimValue.toString().trim();
    return stringValue.isEmpty() ? null : stringValue;
  }

  @SuppressWarnings("unchecked")
  private Object getNestedValue(Map<?, ?> claims, String path) {
    Object current = claims;
    for (String part : path.split("\\.")) {
      if (!(current instanceof Map<?, ?> currentMap)) {
        return null;
      }
      current = ((Map<String, Object>) currentMap).get(part);
      if (current == null) {
        return null;
      }
    }
    return current;
  }
}
