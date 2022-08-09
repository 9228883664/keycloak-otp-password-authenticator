package ppp.plugin.keycloak.login;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.CredentialRepresentation;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class OtpPasswordAuthenticator extends AbstractDirectGrantAuthenticator {

    private static final Logger logger = Logger.getLogger(OtpPasswordAuthenticator.class);
    private static final String OTP_PASSWORD_CONDITIONAL_USER_ATTRIBUTE = "login-with-otp";
    public static final String PROVIDER_ID = "direct-grant-validate-otp-password";
    private static final String error = "OTP validation api error";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String loginWithOtp = retrieveLoginWithOtp(context);
        // Normal login with password code
        if(loginWithOtp==null || !"true".equalsIgnoreCase(loginWithOtp)){
            String password = retrievePassword(context);
            boolean valid = context.getSession().userCredentialManager().isValid(context.getRealm(), context.getUser(), UserCredentialModel.password(password));
            if (!valid) {
                context.getEvent().user(context.getUser());
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
                return;
            }
            context.success();
        }
        // Login with OTP flow
        else{
            int valid = validateOTP(context);
            if(valid==1){
                context.success();
            }
            else if(valid<1){
                context.getEvent().user(context.getUser());
                context.getEvent().error(error);
                Response challengeResponse = errorResponse(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "invalid_grant", "Invalid user credentials");
                context.failure(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
            }
            else{
                context.getEvent().user(context.getUser());
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            }
        }
    }

    private int validateOTP(AuthenticationFlowContext context) {
        int flag = 0;
        UserModel user = context.getUser();
        logger.debug("verify-login-otp for "+ user.getUsername());
        String totp = retrieveOtp(context);
        String url = getOtpValidationUrl(context);
        logger.debug("verify-login-otp url="+url);

        flag=restCall(url, user.getUsername(), totp);
        if(flag>0){
            logger.info("verify-login-otp for "+ user.getUsername() + " successful");
        }
        else if(flag<0){
            logger.info("loginWithOtp for "+ user.getUsername() + " fail due to error");
        }
        else{
            logger.info("loginWithOtp for "+ user.getUsername() + " fail");
        }
        return flag;
    }

    private int restCall(String url, String mobileNo, String otp){
        int flag=0;
        // TODO: remove below logic if external api is working fine
        if("123456".equals(otp)){
            return 1;
        }
        try {
            HttpURLConnection conn = (HttpURLConnection) (new URL(url)).openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");

            StringBuilder jsonRequest = new StringBuilder();
            jsonRequest.append("{ \"otp\": \"");
            jsonRequest.append(otp);
            jsonRequest.append("\",\"username\": \"");
            jsonRequest.append(mobileNo);
            jsonRequest.append("\"}");

            OutputStream streamOtp = conn.getOutputStream();
            streamOtp.write(jsonRequest.toString().getBytes());
            int status = conn.getResponseCode();
             if(status==200){
                flag=1;
                BufferedReader brOtp = new BufferedReader(new InputStreamReader((conn.getInputStream())));

                StringBuilder response = new StringBuilder();
                String responseSingle = null;
                while ((responseSingle = brOtp.readLine()) != null)
                {
                    response.append(responseSingle);
                }
                String jsonResponse = response.toString();
                conn.disconnect();
            }
            else if(status==400){
                flag=0;
            }
            else{
                flag=-1;
            }
        }catch (Exception e){
            e.printStackTrace();
            flag=-1;
        }
        return flag;
    }

    private String getOtpValidationUrl(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel.getConfig();
        String url = config.get(OtpPasswordAuthenticatorFactory.OTP_VALIDATION_EXTERNAL_SERVICE_URL);
        return url ;
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public String getDisplayType() {
        return "PasswordOtp";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "Validates the password supplied as a 'password' or otp form parameter in direct grant request";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new LinkedList<>();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    protected String retrievePassword(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        return inputData.getFirst(CredentialRepresentation.PASSWORD);
    }

    protected String retrieveLoginWithOtp(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        return inputData.getFirst(OTP_PASSWORD_CONDITIONAL_USER_ATTRIBUTE);
    }

    protected String retrieveOtp(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        return inputData.getFirst(CredentialRepresentation.TOTP);
    }
}
