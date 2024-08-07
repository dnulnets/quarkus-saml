package eu.stenlund.idproxy;

import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;

import org.apache.hc.core5.net.URIBuilder;
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

import eu.stenlund.idproxy.helper.SAML2Helper;
import eu.stenlund.idproxy.helper.Session;
import eu.stenlund.idproxy.helper.SessionHelper;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import jakarta.annotation.security.PermitAll;
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
	@Inject
	IDProxy idProxy;
	@Inject
	SessionHelper sessionHelper;

	private static final Logger log = Logger.getLogger("SAML2Servlet");

	@Override
	@PermitAll
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		/* Get the cookie */
		Session s = sessionHelper.getSessionCookie (req);

		/* Make sure we got a return URL */
		String redirect = req.getParameter("return");
		if (redirect == null) {
			log.warn("Missing return parameter");
			resp.setStatus(400);
			resp.addCookie(sessionHelper.deleteCookie());
			resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
			resp.addHeader("Content-Type", "text/plain");
			resp.getWriter().write("Unable to authenticate user. Should be replaced with a more elaborate error page.");
			return;
		}

		/* Make sure we got a valid return URL */
		boolean bMatch = false;
		redirect.replaceAll("\\s+", "");
		for (String url : idProxy.getValidReturnURL()) {
			if (redirect.matches(url)) {
				bMatch = true;
			}
		}
		if (!bMatch) {
			log.warn("Invalid return parameter");
			resp.setStatus(400);
			resp.addCookie(sessionHelper.deleteCookie());
			resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
			resp.addHeader("Content-Type", "text/plain");
			resp.getWriter().write("Unable to authenticate user. Should be replaced with a more elaborate error page.");
			return;
		}

		/* Remember the return URL */
		s.redirect = redirect;

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
			s.id = SAML2Helper.generateSecureRandomId();
			bindingContext.setRelayState(s.id);

			/* Set the peer entity context endpoint to the remote IdP */
			SAMLPeerEntityContext peerEntityContext = context.ensureSubcontext(SAMLPeerEntityContext.class);
			SAMLEndpointContext endpointContext = peerEntityContext.ensureSubcontext(SAMLEndpointContext.class);
			endpointContext.setEndpoint(SAML2Helper.urlToSSOEndpoint(idProxy.getIDPSSOEndpoint()));

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
				log.warn("Unable to sign the request, " + e.getMessage());
				resp.setStatus(401);
				resp.addCookie(sessionHelper.deleteCookie());
				resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
				resp.addHeader("Content-Type", "text/plain");
				resp.getWriter().write("Unable to authenticate user. Should be replaced with a more elaborate error page.");
				return;
			}

			/* Set up the Velocity engine */
			VelocityEngine velocityEngine = new VelocityEngine();
			velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "classpath");
			velocityEngine.setProperty("resource.loader.classpath.class",
					"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
			velocityEngine.init();

			SAML2Helper.logSAMLObject((AuthnRequest) context.getMessage());

			/* Set up the POST encoder */
			HTTPPostEncoder encoder = new HTTPPostEncoder();
			encoder.setMessageContext(context);
			encoder.setHttpServletResponseSupplier(NonnullSupplier.of(resp));
			encoder.setVelocityEngine(velocityEngine);

			/* Set the cookie and remove the JWT */
			Cookie nc = sessionHelper.createCookieFromSession(s);
			resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
			if (nc != null)
				resp.addCookie(nc);
			else {
				log.warn("Unable to create session cookie.");
				resp.setStatus(401);
				resp.addCookie(sessionHelper.deleteCookie());
				resp.addHeader("Content-Type", "text/plain");
				resp.getWriter().write("Unable to authenticate user. Should be replaced with a more elaborate error page.");
				return;
			}

			/* Encode the message SAML message */
			try {
				encoder.initialize();
				encoder.encode();
			} catch (ComponentInitializationException | MessageEncodingException e) {
				log.warn("Unable to encode the SAML Message, " + e.getMessage());
				resp.setStatus(401);
				resp.addCookie(sessionHelper.deleteCookie());
				resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
				resp.addHeader("Content-Type", "text/plain");
				resp.getWriter().write("Unable to authenticate user. Should be replaced with a more elaborate error page.");
				return;
			}

		} else {

			/* Create a new JWT cookie, we are already identified */
			JwtClaimsBuilder jcb = Jwt.claims();
			String jwt = jcb
					.subject(s.uid)
					.expiresIn(Duration.ofMinutes(10))
					.audience(idProxy.getSPEntityID())
					.issuer(idProxy
							.getIDPEntityID())
					.sign();
			resp.addCookie(sessionHelper.createCookieFromString(idProxy.getJWTCookieName(),
				idProxy.getJwtCookieDomain(), idProxy.getJwtCookiePath(), jwt));

			/* Redirect us if wanted */
			if (s.redirect != null) {
				resp.sendRedirect(s.redirect);
			} else {
				resp.setStatus(200);
				resp.addHeader("Content-Type", "text/plain");
				resp.getWriter().write("Authenticated: " + s.uid);
			}

		}
	}

	/**
	 * Builds up the authn-request.
	 * 
	 * @return A SAML AuthN-request
	 */
	private AuthnRequest buildAuthnRequest() {

		/* Set up the basic authn request */
		AuthnRequest authnRequest = SAML2Helper.buildSAMLObject(AuthnRequest.class);
		authnRequest.setIssueInstant(Instant.now());
		authnRequest.setDestination(idProxy.getIDPSSOEndpoint());
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);

		/* Set the assertion consumer service URL, build it from the base URL */
		String uri = null;
		try {
			URIBuilder uriBuilder = new URIBuilder(idProxy.getBaseURL()).appendPathSegments("SAML2", "assert");
			uri = uriBuilder.build().toString();
		} catch (URISyntaxException e) {
			log.warn("Error building URI for AuthnRequest: " + e.getMessage());
		}

		if (uri != null)
			authnRequest.setAssertionConsumerServiceURL(uri);

		authnRequest.setID(SAML2Helper.generateSecureRandomId());
		authnRequest.setIssuer(SAML2Helper.buildIssuer(idProxy.getSPEntityID()));
		authnRequest.setNameIDPolicy(SAML2Helper.buildNameIdPolicy());

		/* Set the requested authn context */
		if (idProxy.getContexts().isPresent()) {

			RequestedAuthnContext requestedAuthnContext = SAML2Helper.buildSAMLObject(RequestedAuthnContext.class);
			requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

			idProxy.getContexts().get().forEach(ctx -> {
				AuthnContextClassRef acr = SAML2Helper.buildSAMLObject(AuthnContextClassRef.class);
				acr.setURI(ctx);
				requestedAuthnContext.getAuthnContextClassRefs().add(acr);
			});

			authnRequest.setRequestedAuthnContext(requestedAuthnContext);
		}

		return authnRequest;
	}

}