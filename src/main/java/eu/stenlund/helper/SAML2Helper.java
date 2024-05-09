package eu.stenlund.helper;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.jboss.logging.Logger;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Element;

import eu.stenlund.IDProxyException;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.security.impl.RandomIdentifierGenerationStrategy;
import net.shibboleth.shared.xml.SerializeSupport;
import net.shibboleth.shared.xml.impl.BasicParserPool;

public class SAML2Helper {

	private static final Logger log = Logger.getLogger("SAML2Helper");
	private static final SAML2Helper instance = new SAML2Helper();
	private static final RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
	private Boolean initialized = false;

	private SAML2Helper() {}

	/**
	 * Returns with the singleton of SAML2Util and initializes it if needed.
	 * 
	 * @return The SAML2Util singleton
	 */
	public static SAML2Helper getInstance()
	{
		if (!instance.initialized) {
			instance.init();
			instance.initialized = true;
		}
		return instance;
	}

	/**
	 * Initializes the OpenSAML framework.
	 */
	private void init() {
		
		log.info ("Initialize the security framework");
		Security.addProvider(new BouncyCastleProvider());

		log.info("Initialize OpenSAML");

		try {
			InitializationService.initialize();
		} catch (InitializationException e) {
			log.error("Unable to initialize openSAML, " + e.getMessage());
			throw new IDProxyException("Unable to initialize openSAML", e);
		}

		log.info("Locating the XMLObject registry");
		XMLObjectProviderRegistry registry;
		synchronized (ConfigurationService.class) {
			registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			if (registry == null) {
				log.debug("XMLObjectProviderRegistry did not exist in ConfigurationService");
				registry = new XMLObjectProviderRegistry();
				ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
			}
		}

		log.info("Creating the BasicParserPool");
		BasicParserPool pp = createParserPool();
		registry.setParserPool(pp);
	}

	/**
	 * Create a basic parser pool with default settings.
	 * 
	 * @return Creates a basic parser pool.
	 * @throws ComponentInitializationException
	 */
	public static BasicParserPool createParserPool() {

		BasicParserPool parserPool = new BasicParserPool();
		parserPool.setMaxPoolSize(100);
		parserPool.setCoalescing(true);
		parserPool.setIgnoreComments(true);
		parserPool.setIgnoreElementContentWhitespace(true);
		parserPool.setNamespaceAware(true);
		parserPool.setExpandEntityReferences(false);
		parserPool.setXincludeAware(false);

		final Map<String, Boolean> features = new HashMap<String, Boolean>();
		features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
		features.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
		features.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);

		parserPool.setBuilderFeatures(features);
		parserPool.setBuilderAttributes(new HashMap<String, Object>());

		try {
			parserPool.initialize();
		} catch (ComponentInitializationException e) {
			log.error("Unable to initialize the OpenSAML parser pool, " + e.getMessage());
			throw new IDProxyException("Unable to initialize OpenSAML parser pool, " + e.getMessage());
		}

		return parserPool;
	}

	/**
	 * Creates a SAMLObject of designated type.
	 * 
	 * @param <T>   The type of object
	 * @param clazz The class
	 * @return A SAMLObject
	 */
	@SuppressWarnings("unchecked")
	public static <T> T buildSAMLObject(final Class<T> clazz) {
		T object = null;

		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
		try {
			QName defaultElementName;
			defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException | NoSuchFieldException | SecurityException e) {
			log.error("Unable to create SAMLObject, " + e.getMessage());
			throw new IDProxyException("Unable to create SAMLObject", e);
		}
		return object;
	}

	/**
	 * Generates a secure random identity.
	 * 
	 * @return A random identity
	 */
	public static String generateSecureRandomId() {
		return secureRandomIdGenerator.generateIdentifier();
	}

	/**
	 * Extracts a string value from an attribute value.
	 * 
	 * @param attributeValue The attribute value object
	 * @return A string representing the value
	 */
	public static String getAttributeValue(XMLObject attributeValue)
	{
		return attributeValue == null ?
				null :
				attributeValue instanceof XSString ?
						getStringAttributeValue((XSString) attributeValue) :
						attributeValue instanceof XSAnyImpl ?
								getAnyAttributeValue((XSAnyImpl) attributeValue) :
								attributeValue.toString();
	}

	private static String getStringAttributeValue(XSString attributeValue)
	{
		return attributeValue.getValue();
	}

	private static String getAnyAttributeValue(XSAnyImpl attributeValue)
	{
		return attributeValue.getTextContent();
	}

	/**
	 * Reads a PEM file and returns with the private key.
	 * 
	 * @param file The name of the PEM file
	 * @return The private key
	 */
	public Credential readPrivatePEMKey (String file)
	{
		InputStream inputStream = getClass().getClassLoader().getResourceAsStream(file);
		PEMParser pp = new PEMParser(new InputStreamReader (inputStream));
		PrivateKey pk = null;

		/* Read and parse the file */
		try {
			PrivateKeyInfo info = null;
			Object o = pp.readObject();
			pp.close();
			if (o instanceof PrivateKeyInfo) {
				info = (PrivateKeyInfo) o;
			} else if ( o instanceof PEMKeyPair ) {
				PEMKeyPair keys = (PEMKeyPair) o;
				info = keys.getPrivateKeyInfo();
			} else {
				log.warn("Unable to find a private key in the file " + file);
				throw new IDProxyException("Unable to find a private key in the file " + file);
			}
	
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			pk = converter.getPrivateKey(info);

		} catch (IOException e) {
			log.warn ("Unable to read private key " + file + ", " + e.getMessage());
			throw new IDProxyException("Unable to read private key", e);
		}

		/* Make a credential out of it */
		BasicCredential bcs = new BasicCredential();
        bcs.setPrivateKey(pk);

		return bcs;
	}

	/**
	 * Creates a credential resolver for the certificates in the metadata.
	 * 
	 * @return A metadata credential resolver
	 */
	public static MetadataCredentialResolver getIdPMetadataCredentialResolver(FilesystemMetadataResolver metadataResolver) {

		final MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
		final PredicateRoleDescriptorResolver roleResolver = new PredicateRoleDescriptorResolver(metadataResolver);
		final KeyInfoCredentialResolver keyResolver = DefaultSecurityConfigurationBootstrap
				.buildBasicInlineKeyInfoCredentialResolver();

		metadataCredentialResolver.setKeyInfoCredentialResolver(keyResolver);
		metadataCredentialResolver.setRoleDescriptorResolver(roleResolver);

		try {
			metadataCredentialResolver.initialize();
			roleResolver.initialize();
		} catch (ComponentInitializationException e) {
			log.error("Unable to initialize the metadataresolver, " + e.getMessage());
			throw new IDProxyException("Unable to initialize the metadataresolver", e);
		}

		return metadataCredentialResolver;
	}

	/**
	 * Creates the trust engine for the IdP.
	 * 
	 * @return The trust engine for the IdP
	 */
	private static ExplicitKeySignatureTrustEngine buildIdPTrustEngine(MetadataCredentialResolver metadataCredentialResolver) {
		final KeyInfoCredentialResolver keyInfoResolver = DefaultSecurityConfigurationBootstrap
				.buildBasicInlineKeyInfoCredentialResolver();
		ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(
			metadataCredentialResolver, keyInfoResolver);

		return trustEngine;
	}

	/**
	 * Create the signature validation parameters for the IDP.
	 * 
	 * @return Parameters for the validation
	 */
	private static SignatureValidationParameters buildIdPSignatureValidationParameters(MetadataCredentialResolver metadataCredentialResolver) {
		SignatureValidationParameters validationParameters = new SignatureValidationParameters();
		validationParameters.setSignatureTrustEngine(buildIdPTrustEngine(metadataCredentialResolver));
		return validationParameters;
	}

	/**
	 * Verifys the signature in the message context.
	 * 
	 * @param context The message context.
	 */
	public static void verifySignature(MessageContext context, String entityID, MetadataCredentialResolver metadataCredentialResolver) {
		SecurityParametersContext secParamsContext = context.ensureSubcontext(SecurityParametersContext.class);
		secParamsContext.setSignatureValidationParameters(buildIdPSignatureValidationParameters(metadataCredentialResolver));

		SAMLPeerEntityContext peerEntityContext = context.ensureSubcontext(SAMLPeerEntityContext.class);
		peerEntityContext.setEntityId(entityID);
		peerEntityContext.setRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

		SAMLProtocolContext protocolContext = context.ensureSubcontext(SAMLProtocolContext.class);
		protocolContext.setProtocol(SAMLConstants.SAML20P_NS);

		SAMLProtocolMessageXMLSignatureSecurityHandler signatureValidationHandler = new SAMLProtocolMessageXMLSignatureSecurityHandler();
		try {
			signatureValidationHandler.initialize();
			signatureValidationHandler.invoke(context);
		} catch (MessageHandlerException | ComponentInitializationException e) {
			log.error("Unable to verify signature, " + e.getMessage());
			throw new IDProxyException("Unable to verify signature", e);
		}

		if (!peerEntityContext.isAuthenticated()) {
			throw new IDProxyException("Message was not signed");
		}
	}

	/**
	 * Builds a NameID policy to be used by the authn request.
	 *  
	 * @return A SAML NameID policy
	 */
	public static NameIDPolicy buildNameIdPolicy() {
		NameIDPolicy nameIDPolicy = SAML2Helper.buildSAMLObject(NameIDPolicy.class);
		nameIDPolicy.setAllowCreate(true);
		nameIDPolicy.setFormat(NameIDType.PERSISTENT);
		return nameIDPolicy;
	}

	/**
	 * Creates the issuer for a message.
	 * 
	 * @param is The issuer
	 * @return The issuer
	 */
	public static Issuer buildIssuer(String is) {
		Issuer issuer = SAML2Helper.buildSAMLObject(Issuer.class);
		issuer.setValue(is);
		return issuer;
	}

	/**
	 * Creates a SAML endpoint based on an URL.
	 * 
	 * @param URL The location
	 * @return The SAML endpoint
	 */
	public static Endpoint urlToSSOEndpoint(String URL) {
		SingleSignOnService endpoint = SAML2Helper.buildSAMLObject(SingleSignOnService.class);
		endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		endpoint.setLocation(URL);
		SAML2Helper.logSAMLObject(endpoint);
		return endpoint;
	}

	/**
	 * Pretty print a SAML object.
	 * 
	 * @param object The SAMLObject to print
	 */
	public static void logSAMLObject(final XMLObject object) {
		Element element = null;

		if (object instanceof SignableSAMLObject && ((SignableSAMLObject) object).isSigned()
				&& object.getDOM() != null) {
			element = object.getDOM();
		} else {
			try {
				Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
				out.marshall(object);
				element = object.getDOM();

			} catch (MarshallingException e) {
				log.error(e.getMessage(), e);
			}
		}

		String xmlString = SerializeSupport.prettyPrintXML(element);

		log.info(xmlString);

	}
}
