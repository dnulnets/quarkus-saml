package eu.stenlund;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.servlet.http.Cookie;

/**
 * The session helper object. It is created during startup and creates the
 * encryption key and IV.
 *
 * It also helps with encrypting and decryption of the cookie for the session.
 *
 * @author Tomas Stenlund
 * @since 2022-07-16
 * 
 */
@ApplicationScoped
public class SessionHelper {

    private static final Logger log = Logger.getLogger(SessionHelper.class);

    /**
     * The cookie domain
     */
    @ConfigProperty(name = "eu.stenlund.security.session.cookie.domain")
    String cookieDomain;

    /**
     * The name of the cookie where we stores session information.
     */
    @ConfigProperty(name = "eu.stenlund.security.session.cookie.name")
    public String cookieNameSession;
    private static int MAX_AGE = 600;

    /**
     * The key used for encryption and decryption of the cookie. Generated from
     * the a SHA-256 of the janus.security.cookie.key passphrase.
     */
    private SecretKeySpec secretKey;

    private static String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static String ALGORITHM_BASE = "AES";
    private static int ALGORITHM_IV_LENGTH = 16;
    private static int ALGORITHM_KEY_LENGTH = 32;

    /**
     * Creates the helper and sets up the key.
     * 
     * @throws NoSuchAlgorithmException The system do not support the algorithm.
     */
    public SessionHelper(@ConfigProperty(name = "eu.stenlund.security.session.cookie.key") String cookieKey) {
        if (cookieKey != null) {
            log.info("Using configuration cookie key");
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(cookieKey.getBytes());
                secretKey = new SecretKeySpec(md.digest(), ALGORITHM_BASE);
            } catch (Exception e) {
                log.info("Uanble to create a SHA-256 of the key, generate a random key");
                byte key[] = new byte[ALGORITHM_KEY_LENGTH];
                new SecureRandom().nextBytes(key);
                secretKey = new SecretKeySpec(key, ALGORITHM_BASE);
            }
        } else {
            log.info("No configuration cookie key has been provided, generate a random one");
            byte key[] = new byte[ALGORITHM_KEY_LENGTH];
            new SecureRandom().nextBytes(key);
            secretKey = new SecretKeySpec(key, ALGORITHM_BASE);
        }
    }

    /**
     * Generates a new random key for n number of bits. NOTE! Should be changed to
     * configuration
     * 
     * @param n Number of bits
     * @return A secret key
     * @throws NoSuchAlgorithmException The system do not support the algorithm.
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_BASE);
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /**
     * Generates a random new IvParameterSpec for AES/CBC. NOTE! Should be changde
     * to configuration
     * 
     * @return The new IvParameterSpec
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[ALGORITHM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Decodes raw data and base 64 encode it.
     * 
     * @param data The raw data
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String encrypt(byte data[])
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        // Generate a new IV and encrypt the data
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivps = generateIv();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivps);
        byte[] cipherText = cipher.doFinal(data);

        // Add the IV as the first bytes of the buffer before encoding it
        byte[] iv = ivps.getIV();
        byte[] total = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, total, 0, iv.length);
        System.arraycopy(cipherText, 0, total, iv.length, cipherText.length);

        // Base64 encode the data
        return Base64.getEncoder().encodeToString(total);
    }

    /**
     * Decrypts an array of base64 encoded data.
     * 
     * @param data Base64 data
     * @return Decrypted raw data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decrypt(String data)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        byte[] total = Base64.getDecoder().decode(data);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivpSpec = new IvParameterSpec(total, 0, ALGORITHM_IV_LENGTH);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivpSpec);
        byte[] plainText = cipher.doFinal(total, ALGORITHM_IV_LENGTH, total.length - ALGORITHM_IV_LENGTH);
        return plainText;
    }

    /**
     * Creates a session cookie from session data.
     * 
     * @param js Session data
     * @return A session cookie
     */
    Cookie createCookieFromSession(Session js)
    {
        ByteArrayOutputStream baos = null;
        baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(js);
            oos.close();
        } catch (IOException e) {
            log.warn ("Unable to encode cookie, " + e.getMessage());
            return null;
        }

        String c;
        try {
            c = encrypt(baos.toByteArray());
        } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
                    log.warn ("Unable to encrypt cookie, " + e.getMessage());
                    return null;
        }

        Cookie nc = new Cookie (cookieNameSession, c);
        nc.setSecure(true);
        nc.setHttpOnly(true);
        nc.setMaxAge(MAX_AGE);
        nc.setPath("/");
        nc.setDomain(getDomain());
        nc.setAttribute("SameSite", "Lax");

        return nc;
    }

    /**
     * Creates a delete cookie for the session cookie.
     *
     * @return Session cookie
     */
    public Cookie deleteCookie() {
        Cookie nc = new Cookie (cookieNameSession, "");
        nc.setMaxAge(0);
        return nc;
    }

    /**
     * Creates the session information based on the cookie.
     * 
     * @param cookie Idproxy session cookie
     * @return Session data
     */
    Session createSessionFromCookie(String cookie)
    {
        Session o = null;
        byte[] data;

        try {
            data = decrypt(cookie);
        } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
                    log.warn("Unable to decrypt cookie, " + e.getMessage());
                    return null;
        }

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            o = (Session) ois.readObject();
            ois.close();
        } catch (ClassNotFoundException | IOException e) {
            log.warn("Unable to decode cookie, " + e.getMessage());
            return null;
        }

        return o;
    }

    public static void logSession (Session s)
    {
        log.info ("Session.AuthnID=" + s.authnID);
        log.info ("Session.Id="+s.id);
        log.info ("Session.UID=" + s.uid);
    }

    public String getCookieNameSession() {
        return cookieNameSession;
    }

    public String getDomain() {
        return this.cookieDomain;
    }
}
