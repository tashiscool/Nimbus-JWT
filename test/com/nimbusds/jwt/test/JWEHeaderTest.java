package com.nimbusds.jwt.test;


import java.net.MalformedURLException;
import java.net.URL;

import com.nimbusds.jwt.Base64;
import com.nimbusds.jwt.Base64URL;
import com.nimbusds.jwt.CompressionAlgorithm;
import com.nimbusds.jwt.Header;
import com.nimbusds.jwt.HeaderException;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWEHeader;
import com.nimbusds.jwt.JWK;
import com.nimbusds.jwt.RSAKey;

import junit.framework.TestCase;


/**
 * Tests JWE header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-21)
 */
public class JWEHeaderTest extends TestCase {


	public void testParse() {
	
		// Example header from JWE spec
		
		String s = "{\"alg\":\"RSA1_5\","+
			    "\"enc\":\"A256GCM\"," +
			    "\"iv\":\"__79_Pv6-fg\"," +
			    "\"jku\":\"https://example.com/public_key.jwk\"}";
	
		JWEHeader h = null;
		
		try {
			h = JWEHeader.parse(s);
			
		} catch (HeaderException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertNull(h.getType());
		assertEquals(JWA.RSA1_5, h.getAlgorithm());
		assertEquals(JWA.A256GCM, h.getEncryptionMethod());
		assertEquals(new Base64URL("__79_Pv6-fg"), h.getInitializationVector());
		assertEquals("https://example.com/public_key.jwk", h.getJWKURL().toString());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
	
		JWEHeader h = new JWEHeader(JWA.RSA1_5);
		
		h.setType(Header.Type.JWT);
		h.setEncryptionMethod(JWA.A256GCM);
		h.setIntegrityAlgorithm(null);
		h.setInitializationVector(new Base64URL("abc"));
		h.setCompressionAlgorithm(CompressionAlgorithm.DEF);
		h.setJWKURL(new URL("https://example.com/jku.json"));
		h.setKeyID("1234");
		
		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final JWK.Use use = JWK.Use.ENCRYPTION;
		final String kid = "1234";
		
		RSAKey jwk = new RSAKey(mod, exp, use, kid);
		
		h.setPublicKey(jwk);
		h.setX509CertURL(new URL("https://example/cert.b64"));
		h.setX509CertThumbprint(new Base64URL("789iop"));
		
		Base64[] certChain = new Base64[3];
		certChain[0] = new Base64("asd");
		certChain[1] = new Base64("fgh");
		certChain[2] = new Base64("jkl");
		
		h.setX509CertChain(certChain);
		
		
		String s = h.toString();
		
		// Parse back
		
		try {
			h = JWEHeader.parse(s);
			
		} catch (HeaderException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertEquals(JWA.RSA1_5, h.getAlgorithm());
		assertEquals(Header.Type.JWT, h.getType());
		assertEquals(JWA.A256GCM, h.getEncryptionMethod());
		assertNull(h.getIntegrityAlgorithm());
		assertEquals("abc", h.getInitializationVector().toString());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals("https://example.com/jku.json", h.getJWKURL().toString());
		assertEquals("1234", h.getKeyID());
		
		jwk = (RSAKey)h.getPublicKey();
		assertNotNull(jwk);
		assertEquals("abc123", jwk.getModulus().toString());
		assertEquals("def456", jwk.getExponent().toString());
		assertEquals(JWK.Use.ENCRYPTION, jwk.getUse());
		assertEquals("1234", jwk.getKeyID());
		
		assertEquals("https://example/cert.b64", h.getX509CertURL().toString());
		assertEquals("789iop", h.getX509CertThumbprint().toString());
		
		certChain = h.getX509CertChain();
		assertEquals(3, certChain.length);
		assertEquals("asd", certChain[0].toString());
		assertEquals("fgh", certChain[1].toString());
		assertEquals("jkl", certChain[2].toString());
	}
}
