package applet;

/**
 * Exception signaling that error occurred during Emerald protocol.
 *
 * <p>This can be caused by unexpected APDU, incorrect values during key agreement
 * ({@link SecureChannelManagerBase} and subclasses), invalid integrity of encrypted messages,
 * incorrect values of messages, unexpected repeated APDU, ...
 * 
 * <p><b>This exception raises security alert.</b>
 */
public class EmeraldProtocolException extends Exception {

    public EmeraldProtocolException() {
    }

    public EmeraldProtocolException(Throwable cause) {
        super(cause);
    }
}
