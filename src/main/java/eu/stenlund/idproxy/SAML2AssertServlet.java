package eu.stenlund.idproxy;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.xmlsec.encryption.support.Decrypter;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;

import eu.stenlund.idproxy.helper.SAML2Helper;
import eu.stenlund.idproxy.helper.Session;
import eu.stenlund.idproxy.helper.SessionHelper;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;

import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;

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

@WebServlet(name = "SAML2Assert", urlPatterns = "/SAML2/assert")
public class SAML2AssertServlet extends HttpServlet {

	private static final Logger log = Logger.getLogger("SAML2AssertServlet");
	@Inject IDProxy idProxy;
	@Inject SessionHelper sessionHelper;

	@Override
	@PermitAll
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		/* Get the cookie */
		Session s = sessionHelper.getSessionCookie (req);
		
		/* If we do not get a cookie, we ignore this POST */
		if (s!=null) {

			/* Did we get a correct cookie */
			if (s.uid != null || s.id == null || s.authnID == null) {

				log.warn("Invalid combination of assertion and cookie");
				resp.addCookie(sessionHelper.deleteCookie());
				resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
				resp.setStatus(401);
				resp.addHeader("Content-Type", "text/plain");
				resp.getWriter().write("Unable to authenticate user");

			} else {

				/* Start decoding the message */
				HTTPPostDecoder decoder = new HTTPPostDecoder();
				NonnullSupplier<HttpServletRequest> supplier = NonnullSupplier.of(req);
				decoder.setHttpServletRequestSupplier(supplier);

				Set<String> uid = new HashSet<>();
				try {

					/* Retrieve the message */
					decoder.initialize();
					decoder.decode();
					MessageContext messageContext = decoder.getMessageContext();
					Response response = (Response) messageContext.getMessage();
					
					/* Verify relaystate and inresponse to */
					SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class);
					String r = bindingContext.getRelayState();

					log.info ("Message.RelayState = " + r);
					log.info ("Message.InResponseTo = " + response.getInResponseTo());
					if (r.compareTo(s.id) != 0 || response.getInResponseTo().compareTo(s.authnID)!=0) {
						log.warn ("Invalid relaystate and/or InResponseTo");
						resp.setStatus(401);
						resp.addHeader("Content-Type", "text/plain");
						resp.getWriter().write("Unable to authenticate user");
						return;
					}

					/* Check status code */
					Status sts = response.getStatus();
					if (sts.getStatusCode().getValue().compareTo(StatusCode.SUCCESS) != 0)
					{
						String v = sts.getStatusMessage().getValue();
						log.warn ("Unable to identify user, " + v);
						resp.setStatus(401);
						resp.addCookie(sessionHelper.deleteCookie());
						resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
						resp.addHeader("Content-Type", "text/plain");
						resp.getWriter().write("Unable to authenticate user, " + v);
						return;
					}

					/* Verify the signature */
					MetadataCredentialResolver metadataCredentialResolver = SAML2Helper.getIdPMetadataCredentialResolver(idProxy.getFilesystemMetadataResolver());
					SAML2Helper.verifySignature(messageContext, idProxy.getIDPEntityID(), metadataCredentialResolver);

					/* Decrypt the assertion */
					StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(idProxy.getEncryptionCredential());
					Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
					decrypter.setRootInNewDocument(true);

					/* Extract the user identity from the assertion */
					uid = response.getEncryptedAssertions()
						.stream()
							.map(ea->handleAssert(decrypter, ea))
							.filter(Optional::isPresent)
							.map(Optional::get)
							.collect(Collectors.toSet());

					/* Did we get any uid? */
					if (uid.size() != 1) {
						log.warn ("Unable to identify user, " + uid.size());
						resp.setStatus(401);
						resp.addCookie(sessionHelper.deleteCookie());
						resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
						resp.addHeader("Content-Type", "text/plain");
						resp.getWriter().write("Unable to authenticate user");
						return;
					}

					/* Set up the cookie */
					s.uid = uid.iterator().next();
					s.id = null;
					s.authnID = null;
					Cookie c = sessionHelper.createCookieFromSession(s);
					if (c != null) {
						resp.addCookie(c);
						JwtClaimsBuilder jcb = Jwt.claims();
						String jwt = jcb
							.subject(s.uid)
							.expiresIn(Duration.ofMinutes(10))
							.audience(idProxy.getSPEntityID())
							.issuer(idProxy
							.getIDPEntityID())
							.preferredUserName(s.uid)
							.issuedAt(Instant.now())
							.sign();
						resp.addCookie(sessionHelper.createCookieFromString(idProxy.getJWTCookieName(), idProxy.getJwtCookieDomain(), idProxy.getJwtCookiePath(), jwt));

						/* If we have a redirect, send us there */
						if (s.redirect != null) {
							resp.sendRedirect(s.redirect);
						} else {
							resp.setStatus(200);
							resp.addHeader("Content-Type", "text/plain");
							resp.getWriter().write("Authenticated: " + uid.iterator().next());
						}

					} else {
						log.warn("Unable to create cookie");
						resp.setStatus(401);
						resp.addCookie(sessionHelper.deleteCookie());
						resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
						resp.addHeader("Content-Type", "text/plain");
						resp.getWriter().write("Unable to authenticate user");
					}

				} catch (ComponentInitializationException | MessageDecodingException e) {
					log.warn ("Unable to accept or decode response, " + e.getMessage());
					resp.setStatus(401);
					resp.addCookie(sessionHelper.deleteCookie());
					resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
					resp.addHeader("Content-Type", "text/plain");
					resp.getWriter().write("Unable to authenticate user");

				}

			}

		} else {

			log.warn("Missing cookie");
			resp.addCookie(sessionHelper.deleteCookie());
			resp.addCookie(sessionHelper.deleteCookieNamed(idProxy.getJWTCookieName()));
			resp.setStatus(401);
			resp.addHeader("Content-Type", "text/plain");
			resp.getWriter().write("Unable to authenticate user");

		}

	}

	/**
	 * Decrypts and check the assertions validity and extract the user id.
	 * 
	 * @param decrypter The decrypter for this assertion
	 * @param ea The encrypted assertion
	 * @return The user id
	 */
	private Optional<String> handleAssert (Decrypter decrypter, EncryptedAssertion ea)
	{
		Assertion a;
		try {
			a = (Assertion)decrypter.decryptData(ea.getEncryptedData());
			SAML2Helper.logSAMLObject(a);
		} catch (DecryptionException e) {
			log.warn ("Unable to decrypt assertion, " + e.getMessage());
			throw new IDProxyException("Unable to decrypt assertion", e);
		}

		/* Verify issuer */
		if (a.getIssuer().getValue().compareTo(idProxy.getIDPEntityID()) != 0) {
			log.warn ("Wrong issuer, " + a.getIssuer().getValue());
			throw new IDProxyException("Wrong issuer, " + a.getIssuer().getValue());
		}

		/* Verify audience */
		List<AudienceRestriction> la = a.getConditions().getAudienceRestrictions();
		Boolean bAudience = false;
		for (AudienceRestriction ar : la) {

			List<Audience> lad = ar.getAudiences();
			for (Audience ad : lad)
				bAudience = ad.getURI().compareTo(idProxy.getSPEntityID())==0;

		}
		if (!bAudience) {
			log.warn ("Correct audience missing, " + idProxy.getSPEntityID());
			throw new IDProxyException("Correct audience missing, " + idProxy.getSPEntityID());
		}

		/* Verify authncontext */
		if (idProxy.getContexts().isPresent()) {

			List<AuthnStatement> laus = a.getAuthnStatements();
			Boolean bContext = false;
			for (AuthnStatement as : laus) {
				AuthnContext ac = as.getAuthnContext();
				String uri = ac.getAuthnContextClassRef().getURI();
				bContext = bContext | idProxy.getContexts().get().contains (uri);
			}
			if (!bContext) {
				log.warn ("Correct authentication context is missing");
				throw new IDProxyException("Correct authentication context is missing");
			}

		}

		/* Try to locate the user id */
		Set<String> uid = new HashSet<>();
		List<AttributeStatement> las = a.getAttributeStatements();
		for (AttributeStatement as : las) {

			List<Attribute> ll = as.getAttributes();
			for (Attribute aa : ll) {
				
				if (aa.getName().compareTo(idProxy.getIdpUID())==0 || 
					aa.getFriendlyName().compareTo(idProxy.getIdpFriendlyUID())==0) {	

					if(aa.getAttributeValues().size() > 0) {

						aa.getAttributeValues().forEach(av->uid.add(SAML2Helper.getAttributeValue(av)));

					}
				}
			}

			uid.forEach(u -> log.info ("Found user identities = " + u));

		}

		/* Did we get any uid or too many, we only support one for now */
		if (uid.size() != 1) {
			log.warn ("Unable to identify user, " + uid.size());
			return Optional.empty();
		} else
			return Optional.of (uid.iterator().next());
	}
}