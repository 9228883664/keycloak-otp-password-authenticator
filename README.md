# keycloak-otp-password-authenticator
Keycloak plugin for authentication and generate token for login with OTP/Password in one API

Systematically guide to run this plugin
1.	Feature description
2.	Plugin Development
3.	Plugin Deployment
4.	Plugin Configuration
5.	Validate APIs using sample payload


======================================================================

#1.	Feature description

Requirement is to use keycloak for OTP validation as primary login. Many portal want either user can login with username/password or can do login by entering registered mobile number and enter received OTP on portal to login. Valid token needs to be generated by calling keycloak API. This plugin serve the purpose of both user can login with either password or OTP. OOTB keycloak does not provide this feature, instead it provide 2F OTP authenticator with well-known OTP application. 

======================================================================

#2.	Plugin Development

Need to develop plugin for direct grant authenticator, which validate token api request and generate valid token if parameters are valid. Source code can be downloaded from below link.
https://github.com/9228883664/keycloak-otp-password-authenticator.git

	##a.	pom.xml file

	    <properties>
		<keycloak.version>16.1.1</keycloak.version>
		<jboss-jaxrs-api_2.1_spec>2.0.2.Final</jboss-jaxrs-api_2.1_spec>
		<maven.compiler.source>8</maven.compiler.source>
		<maven.compiler.target>8</maven.compiler.target>
		<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
		<apache.httpcomponents.version>4.5.13</apache.httpcomponents.version>
	    </properties>


	##b.	OtpPasswordAuthenticator extends AbstractDirectGrantAuthenticator
	Create one class that implements Abstract Direct Grant Authenticator class
		@Override
		public void authenticate(AuthenticationFlowContext context) {
		    String loginWithOtp = retrieveLoginWithOtp(context);
		    // Normal login with password code
		    if(loginWithOtp==null || !"true".equalsIgnoreCase(loginWithOtp)){
			String password = retrievePassword(context);
			boolean valid = context.getSession().userCredentialManager()
				.isValid(context.getRealm(), context.getUser(), UserCredentialModel.password(password));
			if (!valid) {
			    context.getEvent().user(context.getUser());
			    context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
			    Response challengeResponse = 
				errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), 
					"invalid_grant", "Invalid user credentials");
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
			    Response challengeResponse = errorResponse(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),   
						"invalid_grant", "Invalid user credentials");
			    context.failure(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
			}
			else{
			    context.getEvent().user(context.getUser());
			    context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
			    Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), 
					"invalid_grant", "Invalid user credentials");
			    context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
			}
		    }
		}


	##c.	OtpPasswordAuthenticatorFactory implements AuthenticatorFactory
	Implement one Factory class to provide configuration 
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

	##d.	org.keycloak.authentication.AuthenticatorFactory
		Set configuration factory in meta info
		ppp.plugin.keycloak.login.OtpPasswordAuthenticatorFactory

======================================================================

#3.	Plugin Deployment

	Download keycloak 16.1.1 or any latest version with any server. For JBoss we can do below steps.
	Generate spring boot jar file using mvn clean install. Copy jar file and paste in jboss standalone folder.
	Copy From: keycloak-otp-password-authenticator/target/keycloak-otp-password-authenticator_v1.0.jar
	Copy To: keycloak-16.1.1/standalone/deployments/keycloak-otp-password-authenticator_v1.0.jar

	Start Jboss after this using standalone command 
	Check log with below string for successful deployment: 
	Deployed "keycloak-otp-password-authenticator_v1.0.jar"
	Check http://localhost:8080/auth for UI

======================================================================

#4.	Plugin Configuration

	Configure plugin on keycloak ui.
	##a.	Create new or copy from direct grant flow in ppp realm Authentication Flow.
		Here new flow name given otp-password-authenticator.
		Clean all action and keep Username Validation execution flow.

		Now click on add execution and add “otp password authenticator” execution in flow.
		Now configure new execution with values by clicking action->config.

	##b.	Change direct grant auth flow
		Change Binding of Direct Grant Flow to “otp-password-authenticator” flow, which is created in above step, and save configuration

======================================================================

**5.	Validate APIs using sample payload

	Call token API as per below payload where new parameters added for OTP
	
	Below is the regular password call
	
	_curl --location --request POST '{{keycloak-url}}/realms/dep7/protocol/openid-connect/token' \
	--header 'Content-Type: application/x-www-form-urlencoded' \
	--data-urlencode 'client_id={{client-id}}' \
	--data-urlencode 'client_secret={{secret}}' \
	--data-urlencode 'grant_type=password' \
	--data-urlencode 'username={{username}}' \
	--data-urlencode 'password={{password}}'_

	Below is the otp call
	
	_curl --location --request POST '{{keycloak-url}}/realms/dep7/protocol/openid-connect/token' \
	--header 'Content-Type: application/x-www-form-urlencoded' \
	--data-urlencode 'client_id={{client-id}}' \
	--data-urlencode 'client_secret={{secret}}' \
	--data-urlencode 'grant_type=password' \
	--data-urlencode 'username={{username}}' \
	--data-urlencode 'totp={{otp}}' \
	--data-urlencode 'login-with-otp=true'_






