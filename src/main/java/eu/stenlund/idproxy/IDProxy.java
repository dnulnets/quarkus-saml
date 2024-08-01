package eu.stenlund.idproxy;

import java.io.File;
import java.util.List;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;

import eu.stenlund.idproxy.helper.SAML2Helper;
import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * The IDProxy class represents a proxy for Identity Providers (IdPs) in a SAML-based authentication system.
 * It provides methods to retrieve information from the IdP metadata, such as the Single Sign-On (SSO) endpoint,
 * entity ID, signing and encryption credentials, and other configuration values.
 */
@ApplicationScoped
public class IDProxy {

	private static final Logger log = Logger.getLogger(IDProxy.class);

	/**
	 * The information extracted from the metadata.
	 */
	private FilesystemMetadataResolver metadataResolver = null;

	/**
	 * The IdP:s POST SSO endpoint, extracted from the metadata.
	 */
	private String idpSSOEndpoint = "";

	/**
	 * Values from the configuration file
	 */
	@ConfigProperty(name = "idproxy.idp.metadata")
	String metadata;
	@ConfigProperty(name = "idproxy.idp.entityID")
	String idpEntityID;
	@ConfigProperty(name = "idproxy.idp.uid", defaultValue = "urn:oid:0.9.2342.19200300.100.1.1")
	String idpUID;
	@ConfigProperty(name = "idproxy.idp.friendlyUID", defaultValue = "uid")
	String idpFriendlyUID;

	@ConfigProperty(name = "idproxy.sp.entityID")
	String spEntityID;
	@ConfigProperty(name = "idproxy.sp.signing.pem")
	String spPEMSigning;
	@ConfigProperty(name = "idproxy.sp.encryption.pem")
	String spPEMEncryption;

	@ConfigProperty(name = "idproxy.security.jwt.cookie.name", defaultValue = "ID")
	String jwtCookieName;
	@ConfigProperty(name = "idproxy.security.jwt.cookie.path")
	String jwtCookiePath;
	@ConfigProperty(name = "idproxy.security.jwt.cookie.domain")
	String jwtCookieDomain;

	@ConfigProperty(name = "idproxy.base-url")
	String baseURL;
	@ConfigProperty(name = "idproxy.valid-return-url")
	List<String> validReturnURL;

	/* SP information */
	private Credential spSigning = null;
	private Credential spEncryption = null;

	private static final String[] contexts = {
		"http://id.swedenconnect.se/loa/1.0/uncertified-loa3",
		"http://id.swedenconnect.se/loa/1.0/uncertified-eidas-sub",
		"http://id.swedenconnect.se/loa/1.0/uncertified-eidas-high"};

	@Startup
	void init()
	{
		log.info ("Initializing the IDProxy Application");

		/* Initializes it by calling getInstance for the first time */
		SAML2Helper.getInstance();

		/* Read and parse the IdP metadata file */
		try {
			File metadataFile = new File(metadata);
			metadataResolver = new FilesystemMetadataResolver(metadataFile);
			metadataResolver.setId(metadataResolver.getClass().getCanonicalName());
			metadataResolver.setParserPool(SAML2Helper.createParserPool());
			metadataResolver.initialize();
		} catch (ResolverException | ComponentInitializationException e) {
			log.error ("Unable to read and parse metadata," + e.getMessage());
			throw new IDProxyException("Unable to read and parse the metadata", e);
		}

		/* Get some information from the metadata */
		parseIDPMetadata(idpEntityID);

		/* Read the signing and the encryption keys */
		spSigning = SAML2Helper.getInstance().readPrivatePEMKey(spPEMSigning);
		spEncryption = SAML2Helper.getInstance().readPrivatePEMKey(spPEMEncryption);
	
    }

	/**
	 * Extract information needed from the metadata of the IdP:s.
	 * 
	 * @param eID Entity id of the IdP in the metadata.
	 */
	private void parseIDPMetadata(String eID) {
		
		/* Start fresh */
		idpSSOEndpoint = "";

		/* Locate the SingleSignOnService endpoint for the POST binding */
		for (EntityDescriptor e : metadataResolver) {

			/* We are only interested in the entityid we want to use as IdP */
			if (e.getEntityID().compareTo(eID) == 0) {
				IDPSSODescriptor idp = e.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
				for (SingleSignOnService ssos : idp.getSingleSignOnServices()) {
					if (ssos.getBinding().compareTo(SAMLConstants.SAML2_POST_BINDING_URI) == 0) {
						if (idpSSOEndpoint.isEmpty()) {
							idpSSOEndpoint = ssos.getLocation();
						} else {
							log.error("Multiple SingleSignOnService endpoints for POST binding");
							throw new IDProxyException("Multiple SingleSignOnService endpoints for POST binding");
						}
					}
				}
			}
		}

		/* Did we get the endpoint? Fail otherwise */
		if (idpSSOEndpoint.isEmpty()) {
			log.error("No SingleSignOnService endpoint for POST binding found in the IdP metadata");
			throw new IDProxyException("No SingleSignOnService endpoint for POST binding found in the IdP metadata");
		}
	}

	public String getIDPSSOEndpoint() {
		return idpSSOEndpoint;
	}

	public String getIDPEntityID() {
		return idpEntityID;
	}

	public Credential getSigningCredential() {
		return spSigning;

	}

	public Credential getEncryptionCredential() {
		return spEncryption;
	}

	public String getSPEntityID ()
	{
		return spEntityID;
	}

	public FilesystemMetadataResolver getFilesystemMetadataResolver()
	{
		return metadataResolver;
	}

	public static String[] getContexts()
	{
		return contexts;
	}

	public String getJWTCookieName()
	{
		return jwtCookieName; 
	}

	public String getJwtCookiePath() {
		return jwtCookiePath;
	}

	public String getJwtCookieDomain() {
		return jwtCookieDomain;
	}

	public String getBaseURL() {
		return baseURL;
	}

	public String getIdpUID() {
		return idpUID;
	}

	public String getIdpFriendlyUID() {
		return idpFriendlyUID;
	}

	public List<String> getValidReturnURL() {
		return validReturnURL;
	}
}
