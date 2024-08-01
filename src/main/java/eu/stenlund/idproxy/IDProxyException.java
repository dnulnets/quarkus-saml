package eu.stenlund.idproxy;

/**
 * This class represents an exception specific to the IDProxy application.
 * It is a subclass of the RuntimeException class.
 */
public class IDProxyException extends RuntimeException {

    /**
     * Constructs a new IDProxyException with the specified error message.
     *
     * @param errorMessage the error message associated with the exception
     */
    public IDProxyException(String errorMessage) {
        super(errorMessage);
    }

    /**
     * Constructs a new IDProxyException with the specified error message and cause.
     *
     * @param errorMessage the error message associated with the exception
     * @param cause        the cause of the exception
     */
    public IDProxyException(String errorMessage, Throwable cause) {
        super(errorMessage, cause);
    }

}