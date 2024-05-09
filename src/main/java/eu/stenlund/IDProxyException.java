package eu.stenlund;

public class IDProxyException extends RuntimeException {

    /**
     * @param errorMessage
     */
    public IDProxyException(String errorMessage) {
        super(errorMessage);
    }

    /**
     * @param errorMessage
     * @param cause
     */
    public IDProxyException(String errorMessage, Throwable cause) {
        super(errorMessage, cause);
    }

}