package six.six.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberFormat;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

import six.six.keycloak.KeycloakSmsConstants;
import six.six.keycloak.requiredaction.action.required.KeycloakSmsMobilenumberRequiredAction;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.Date;
import java.util.List;

/**
 * Created by joris on 11/11/2016.
 */
public class KeycloakSmsAuthenticator implements Authenticator {

    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticator.class);

    public static final String CREDENTIAL_TYPE = "sms_validation";

    private enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }


    private boolean isOnlyForVerificationMode(boolean onlyForVerification,String mobileNumber,String mobileNumberVerified){
        return (mobileNumber ==null || onlyForVerification==true && !mobileNumber.equals(mobileNumberVerified) );
    }

    private String getMobileNumber(UserModel user){
    	String mobileNumber = null;
    	
    	if (user != null) {
//	        List<String> mobileNumberCreds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE);
//	
//	        
//	        if (mobileNumberCreds != null && !mobileNumberCreds.isEmpty()) {
//	            mobileNumber = mobileNumberCreds.get(0);
//	        }
    		mobileNumber = user.getUsername();
    	}

        return  mobileNumber;
    }

    private String getMobileNumberVerified(UserModel user){
    	String mobileNumberVerified = null;
    
    	if (user != null) {
	        List<String> mobileNumberVerifieds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED);
	
	        if (mobileNumberVerifieds != null && !mobileNumberVerifieds.isEmpty()) {
	            mobileNumberVerified = mobileNumberVerifieds.get(0);
	        }
    	}
    	
        return  mobileNumberVerified;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
    	logger.debug("authenticate called ... context = " + context);
        UserModel user = context.getUser();
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        if (user == null) {
        	Response challenge = context.form().createForm("sms-validation-mobile-number-login.ftl");
            context.challenge(challenge);
        }
        else {        
	        boolean onlyForVerification = KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_VERIFICATION_ENABLED);
	
	        String mobileNumber = getMobileNumber(user);
	        String mobileNumberVerified = getMobileNumberVerified(user);
	
	        if (onlyForVerification==false || isOnlyForVerificationMode(onlyForVerification, mobileNumber,mobileNumberVerified)){
	            if (mobileNumber != null) {
	                // The mobile number is configured --> send an SMS
	                long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(config, KeycloakSmsConstants.CONF_PRP_SMS_CODE_LENGTH, 8L);
	                logger.debug("Using nrOfDigits " + nrOfDigits);
	
	
	                long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(config, KeycloakSmsConstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s
	
	                logger.debug("Using ttl " + ttl + " (s)");
	
	                String code = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);
	
	                storeSMSCode(context, user, code, new Date().getTime() + (ttl * 1000)); // s --> ms
	                if (KeycloakSmsAuthenticatorUtil.sendSmsCode(mobileNumber, code, context)) {
	                    Response challenge = context.form().createForm("sms-validation.ftl");
	                    context.challenge(challenge);
	                } else {
	                    Response challenge = context.form()
	                            .setError("sms-auth.not.send")
	                            .createForm("sms-validation-error.ftl");
	                    context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
	                }
	            } else {
	                boolean isAskingFor=KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_ASKFOR_ENABLED);
	                if(isAskingFor){
	                    //Enable access and ask for mobilenumber
	                    user.addRequiredAction(KeycloakSmsMobilenumberRequiredAction.PROVIDER_ID);
	                    context.success();
	                }else {
	                    // The mobile number is NOT configured --> complain
	                    Response challenge = context.form()
	                            .setError("sms-auth.not.mobile")
	                            .createForm("sms-validation-error.ftl");
	                    context.failureChallenge(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, challenge);
	                }
	            }
	        }else{
	            logger.debug("Skip SMS code because onlyForVerification " + onlyForVerification + " or  mobileNumber==mobileNumberVerified");
	            context.success();
	
	        }
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.debug("action called ... context = " + context);
        
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        
        UserModel user = context.getUser();
        
        String phoneNumber = null;
        if (user == null) {
	        // get the phone number
	        phoneNumber = getPhoneNumber(context);
	        
	        if (phoneNumber != null && isPhoneNumberValid(phoneNumber)) {
	            phoneNumber = formatNumber(phoneNumber);
	
	            // get the user and set them in context
	            user = context.getSession().users().getUserByUsername(phoneNumber, context.getRealm());
	            if (user != null) {
	            	context.setUser(user);
	            }
	        }
	        else {
	            Response challenge = context.form()
	                    .setError("sms-auth.phone.not.valid")
	                    .createForm("sms-validation-mobile-number-login.ftl");
	            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
	            return;
	        }
        }
        else {
        	phoneNumber = user.getUsername();
        }
        
        if (user != null) {
        	// get the OTP code from the authenticated model
        	String storedOTP = getStoredCode(context, user);
        	String userEnteredOTP = getCode(context);
        	
        	if (storedOTP == null || storedOTP.isEmpty()) {
        		// no OTP - send one
                long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(config, KeycloakSmsConstants.CONF_PRP_SMS_CODE_LENGTH, 8L);
                logger.debug("Using nrOfDigits " + nrOfDigits);

                long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(config, KeycloakSmsConstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s

                logger.debug("Using ttl " + ttl + " (s)");

                String generatedOTP = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);

                storeSMSCode(context, user, generatedOTP, new Date().getTime() + (ttl * 1000)); // s --> ms
                if (KeycloakSmsAuthenticatorUtil.sendSmsCode(phoneNumber, generatedOTP, context)) {
                    Response challenge = context.form().createForm("sms-validation.ftl");
                    context.challenge(challenge);
                } else {
                    Response challenge = context.form()
                            .setError("sms-auth.not.send")
                            .createForm("sms-validation-error.ftl");
                    context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                }
        	}
        	else {
        		if (userEnteredOTP == null || userEnteredOTP.isEmpty()) {
                    Response challenge = context.form().createForm("sms-validation.ftl");
                    context.challenge(challenge);
        		}
        		else {
        			// have both a stored and incoming code - verify
        		
	        		// The mobile number is configured --> send an SMS
	                CODE_STATUS status = validateCode(context);
	                Response challenge = null;
	                switch (status) {
	                    case EXPIRED:
	                        challenge = context.form()
	                                .setError("sms-auth.code.expired")
	                                .createForm("sms-validation.ftl");
	                        context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
	                        break;
	
	                    case INVALID:
	                        if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.OPTIONAL ||
	                                context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE) {
	                            logger.debug("Calling context.attempted()");
	                            context.attempted();
	                        } else if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
	                            challenge = context.form()
	                                    .setError("sms-auth.code.invalid")
	                                    .createForm("sms-validation.ftl");
	                            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
	                        } else {
	                            // Something strange happened
	                            logger.warn("Undefined execution ...");
	                        }
	                        break;
	
	                    case VALID:
	                        context.success();
	                        updateVerifiedMobilenumber(context);
	                        clearSMSCode(context, user);
	                        break;
	
	                }
        		}
        	}
        }
        else {
            Response challenge = context.form()
                    .setError("sms-auth.phone.not.found")
                    .createForm("sms-validation-mobile-number-login.ftl");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
        }        
    }

    private String formatNumber(String phoneNumber) {
        PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
        PhoneNumber number;
        try {
            number = phoneUtil.parse(phoneNumber, null);
            return phoneUtil.format(number, PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            return phoneNumber;
        }
    }

    private boolean isPhoneNumberValid(String phoneNumber) {
        PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
        PhoneNumber number;
        try {
            number = phoneUtil.parse(phoneNumber, null);
            return phoneUtil.isValidNumber(number);
        } catch (NumberParseException e) {
            return false;
        }
    }

    /**
     * Get the user entered phone number
     */
    protected String getPhoneNumber(AuthenticationFlowContext context) {
	    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
	    return formData.getFirst(KeycloakSmsConstants.ATTR_MOBILE);
    }
    
    /** 
     * Get the user entered OTP
     */
    protected String getCode(AuthenticationFlowContext context) {
    	MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        return formData.getFirst(KeycloakSmsConstants.ANSW_SMS_CODE);
    }
    
    
    /**
     * Get the stored OTP
     * 
     * TODO: expiry
     */
    public String getStoredCode(AuthenticationFlowContext context, UserModel user) {
    	String code = null;
    
    	if (context != null && user != null) {
	    	KeycloakSession session = context.getSession();
	
	        List<CredentialModel> codeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(), user, KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);
	        List<CredentialModel> timeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(), user, KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME);
	        
	        if (codeCreds != null && codeCreds.size() > 0) {
	        	CredentialModel expectedCode = (CredentialModel) codeCreds.get(0);
	        	
	        	if (timeCreds != null && timeCreds.size() > 0) {
		        	CredentialModel expTimeString = (CredentialModel) timeCreds.get(0);
		        	
		        	long expiry = Long.parseLong(expTimeString.getValue());
		        	long now = new Date().getTime();
		        	
		        	if (expiry >= now) {
		        		code = expectedCode.getValue();
		        	}
		        }
	        	
	        }
    	}
    	
    	return code;
    }
    
    /**
     * If necessary update verified mobilenumber
     * @param context
     */
    private void updateVerifiedMobilenumber(AuthenticationFlowContext context){
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        UserModel user = context.getUser();
        boolean onlyForVerification=KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_VERIFICATION_ENABLED);

        if(onlyForVerification){
            //Only verification mode
            List<String> mobileNumberCreds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE);
            if (mobileNumberCreds != null && !mobileNumberCreds.isEmpty()) {
                user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED,mobileNumberCreds);
            }
        }
    }

    // Store the code + expiration time in a UserCredential. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private void storeSMSCode(AuthenticationFlowContext context, UserModel user, String code, Long expiringAt) {
        UserCredentialModel credentials = new UserCredentialModel();
        credentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);
        credentials.setValue(code);

        context.getSession().userCredentialManager().updateCredential(context.getRealm(), user, credentials);

        credentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME);
        credentials.setValue((expiringAt).toString());
        context.getSession().userCredentialManager().updateCredential(context.getRealm(), user, credentials);
    }
    
    // Clear the code + expiration time in a UserCredential. Keycloak will clear these from the DB.
    private void clearSMSCode(AuthenticationFlowContext context, UserModel user) {
    	if (context != null && context != null) {
	    	RealmModel realm = context.getRealm();
	    	
	    	if (realm != null) {
	    		context.getSession().userCredentialManager().removeStoredCredential(
    				realm, 
    				user, 
    				KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE
    			);
	    		context.getSession().userCredentialManager().removeStoredCredential(
	    			realm, 
	    			user, 
	    			KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME
	    		);
	    	}
    	}
    }


    protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        logger.debug("validateCode called ... ");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(KeycloakSmsConstants.ANSW_SMS_CODE);
        KeycloakSession session = context.getSession();

        List codeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(), context.getUser(), KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);
        /*List timeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(), context.getUser(), KeycloakSmsAuthenticatorConstants.USR_CRED_MDL_SMS_EXP_TIME);*/

        CredentialModel expectedCode = (CredentialModel) codeCreds.get(0);
        /*CredentialModel expTimeString = (CredentialModel) timeCreds.get(0);*/

        logger.debug("Expected code = " + expectedCode + "    entered code = " + enteredCode);

        if (expectedCode != null) {
            result = enteredCode.equals(expectedCode.getValue()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            /*long now = new Date().getTime();

            logger.debug("Valid code expires in " + (Long.parseLong(expTimeString.getValue()) - now) + " ms");
            if (result == CODE_STATUS.VALID) {
                if (Long.parseLong(expTimeString.getValue()) < now) {
                    logger.debug("Code is expired !!");
                    result = CODE_STATUS.EXPIRED;
                }
            }*/
        }
        logger.debug("result : " + result);
        return result;
    }
    @Override
    public boolean requiresUser() {
        logger.debug("requiresUser called ... returning true");
        return false;
    }
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("configuredFor called ... session=" + session + ", realm=" + realm + ", user=" + user);
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("setRequiredActions called ... session=" + session + ", realm=" + realm + ", user=" + user);
    }
    @Override
    public void close() {
        logger.debug("close called ...");
    }

}
