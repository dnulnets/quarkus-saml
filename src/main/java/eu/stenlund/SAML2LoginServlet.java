package eu.stenlund;

import java.io.IOException;
import java.time.Instant;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.jboss.logging.Logger;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.impl.BasicKeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;

@WebServlet(name = "SAML2Login", urlPatterns = "/SAML2/login")
public class SAML2LoginServlet extends HttpServlet {

    /**
     * The idproxy singleton.
     */
    @Inject IDProxy idProxy;
	@Inject SessionHelper sessionHelper;

    private static final Logger log = Logger.getLogger("SAML2Servlet");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		/* Get the cookie */
		Session s = new Session();
		if (req.getCookies() != null) {
			for (Cookie c : req.getCookies()) {
				if (c.getName().compareTo(sessionHelper.getCookieNameSession()) == 0)
						s = sessionHelper.createSessionFromCookie(c.getValue());
			}
		}
		SessionHelper.logSession(s);

		/* Create an auth request unless we are already identified */
		if (s.uid == null) {

			/* Get the context */
			MessageContext context = new MessageContext();

			/* Build the redirect message */
			AuthnRequest authn = buildAuthnRequest();
			context.setMessage(authn);

			/* Get the message id */
			s.authnID = authn.getID();

			/* Set the realy state, need this for pairing it together again on the assert */
			SAMLBindingContext bindingContext = context.ensureSubcontext(SAMLBindingContext.class);
			s.id = SAML2Util.generateSecureRandomId();
			bindingContext.setRelayState(s.id);
			
			/* Set the peer entity context endpoint to the remote IdP*/
			SAMLPeerEntityContext peerEntityContext = context.ensureSubcontext(SAMLPeerEntityContext.class);
			SAMLEndpointContext endpointContext = peerEntityContext.ensureSubcontext(SAMLEndpointContext.class);
			endpointContext.setEndpoint(SAML2Util.urlToSSOEndpoint(idProxy.getIDPSSOEndpoint()));

			/* Set the signature parameters */
			SignatureSigningParameters signingParameters = new SignatureSigningParameters();
			signingParameters.setSigningCredential(idProxy.getSigningCredential());
			signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
			signingParameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
			signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			signingParameters.setKeyInfoGenerator(new BasicKeyInfoGeneratorFactory().newInstance());
			context.ensureSubcontext(SecurityParametersContext.class).setSignatureSigningParameters(signingParameters);

			/* Sign the message */
			SAMLOutboundProtocolMessageSigningHandler handler = new SAMLOutboundProtocolMessageSigningHandler();
			handler.setSignErrorResponses(false);
			try {
				handler.initialize();
				handler.invoke(context);
			} catch (ComponentInitializationException | MessageHandlerException e) {
				log.error ("Unable to sign the request, " + e.getMessage());
				resp.setStatus(401);
				resp.addCookie(sessionHelper.deleteCookie());
				resp.addHeader("Content-Type", "text/plain");
				resp.getWriter().write("Unable to authenticate user");
				return;
			}

			/* Set up the Velocity engine */
			VelocityEngine velocityEngine = new VelocityEngine();
			velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "classpath");
			velocityEngine.setProperty("resource.loader.classpath.class",
				"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
			velocityEngine.init();

			SAML2Util.logSAMLObject((AuthnRequest)context.getMessage());

			/* Set up the POST encoder */
			HTTPPostEncoder encoder = new HTTPPostEncoder();
			encoder.setMessageContext(context);
			encoder.setHttpServletResponseSupplier(NonnullSupplier.of(resp));
			encoder.setVelocityEngine(velocityEngine);

			/* Set the cookie */
			SessionHelper.logSession(s);
			Cookie nc = sessionHelper.createCookieFromSession(s);
			if (nc != null)
				resp.addCookie(nc);
			else
				resp.addCookie (sessionHelper.deleteCookie());

			/* Encode the message */
			try {
				encoder.initialize();
				encoder.encode();
			} catch (ComponentInitializationException | MessageEncodingException e) {
				log.error("Unable to encode the SAML Message, " + e.getMessage());
				resp.setStatus(401);
				resp.addCookie(sessionHelper.deleteCookie());
				resp.addHeader("Content-Type", "text/plain");
				resp.getWriter().write("Unable to authenticate user");
				return;
			}

		} else {

			resp.setStatus(200);
			resp.addHeader("Content-Type", "text/plain");
			resp.getWriter().write("Authenticated: " + s.uid);		
	
		}
	}

	/**
	 * Builds up the authn-request.
	 * 
	 * @return A SAML AuthN-request
	 */
	private AuthnRequest buildAuthnRequest() {

		/* Set up the basic authn request */
		AuthnRequest authnRequest = SAML2Util.buildSAMLObject(AuthnRequest.class);
		authnRequest.setIssueInstant(Instant.now());
		authnRequest.setDestination(idProxy.getIDPSSOEndpoint());
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(idProxy.getSPAssertionEndpoint());
		authnRequest.setID(SAML2Util.generateSecureRandomId());
		authnRequest.setIssuer(SAML2Util.buildIssuer(idProxy.getSPEntityID()));
		authnRequest.setNameIDPolicy(SAML2Util.buildNameIdPolicy());

		/* Set the requested authn context */
		RequestedAuthnContext requestedAuthnContext = SAML2Util.buildSAMLObject(RequestedAuthnContext.class);
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
		for (String ctx : IDProxy.getContexts()) {
			AuthnContextClassRef acr = SAML2Util.buildSAMLObject(AuthnContextClassRef.class);
			acr.setURI(ctx);
			requestedAuthnContext.getAuthnContextClassRefs().add(acr);
		}
		authnRequest.setRequestedAuthnContext(requestedAuthnContext);

		return authnRequest;
	}

}