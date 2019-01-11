package six.six.gateway;

/**
 * SMS provder interface
 */
public interface SMSService {
    boolean send(String phoneNumber, String sender, String message, String login, String pw);
}
