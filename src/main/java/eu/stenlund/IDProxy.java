package eu.stenlund;

import java.io.File;
import java.net.URISyntaxException;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;

import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.resolver.ResolverException;

@ApplicationScoped
public class IDProxy {

	private static final Logger log = Logger.getLogger("IDProxy");

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
	@ConfigProperty(name = "eu.stenlund.idp.metadata")
	String metadata;
	@ConfigProperty(name = "eu.stenlund.idp.entityID")
	String idpEntityID;
	@ConfigProperty(name = "eu.stenlund.sp.entityID")
	String spEntityID;
	@ConfigProperty(name = "eu.stenlund.sp.assertion.endpoint")
	String spAssertionEndpoint;
	@ConfigProperty(name = "eu.stenlund.sp.signing.pem")
	String spPEMSigning;
	@ConfigProperty(name = "eu.stenlund.sp.encryption.pem")
	String spPEMEncryption;

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
		SAML2Util.getInstance();

		/* Read and parse the IdP metadata file */
		try {
			File metadataFile = new File(getClass().getClassLoader().getResource(metadata).toURI());
			metadataResolver = new FilesystemMetadataResolver(metadataFile);
			metadataResolver.setId(metadataResolver.getClass().getCanonicalName());
			metadataResolver.setParserPool(SAML2Util.createParserPool());
			metadataResolver.initialize();
		} catch (URISyntaxException | ResolverException | ComponentInitializationException e) {
			log.error ("Unable to read and parse metadata," + e.getMessage());
			throw new IDProxyException("Unable to read and parse the metadata", e);
		}

		/* Get some information from the metadata */
		parseIDPMetadata(idpEntityID);

		/* Read the signing and the encryption keys */
		spSigning = SAML2Util.getInstance().readPrivatePEMKey(spPEMSigning);
		spEncryption = SAML2Util.getInstance().readPrivatePEMKey(spPEMEncryption);
	
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
			log.error("No SingleSignOnService endpoint for POST binding");
			throw new IDProxyException("No SingleSignOnService endpoint in metadata");
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

	public String getSPAssertionEndpoint()
	{
		return spAssertionEndpoint;
	}

	public FilesystemMetadataResolver getFilesystemMetadataResolver()
	{
		return metadataResolver;
	}

	public static String[] getContexts()
	{
		return contexts;
	}
}
