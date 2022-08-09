package ppp.plugin.keycloak.login;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

import java.util.Arrays;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class OtpPasswordAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "otppasswordauthenticator";

    private static final Authenticator AUTHENTICATOR_INSTANCE = new OtpPasswordAuthenticator();
    static final String OTP_VALIDATION_EXTERNAL_SERVICE_URL = "otp-validation-service-url";

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return AUTHENTICATOR_INSTANCE;
    }

    @Override
    public String getDisplayType() {
        return "Otp Password Authenticator";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] { AuthenticationExecutionModel.Requirement.REQUIRED };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Limits access to only valid Otp or password";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty servicename = new ProviderConfigProperty();
        servicename.setType(STRING_TYPE);
        servicename.setName(OTP_VALIDATION_EXTERNAL_SERVICE_URL);
        servicename.setLabel("OTP validation service url");
        servicename.setDefaultValue("http://localhost:8080/api/validateOtp");
        servicename.setHelpText("Valid url for OTP validation e.g. http://localhost:8080/api/validateOtp");

        List<ProviderConfigProperty> listOfConfigs = Arrays.asList(servicename);
        return listOfConfigs;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
