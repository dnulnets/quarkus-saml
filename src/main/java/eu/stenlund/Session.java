package eu.stenlund;

import java.io.Serializable;

/**
 * The session POJO used for serializing the session to and from a cookie.
 *
 * @author Tomas Stenlund
 * @since 2022-07-16
 * 
 */
public class Session implements Serializable {

    /**
     * Version of the object
     */
    private static final long serialVersionUID = 1L;

    public String id = null;
    public String authnID = null;
    public String uid = null;

}

