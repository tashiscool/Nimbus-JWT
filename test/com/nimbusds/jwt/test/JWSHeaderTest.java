package com.nimbusds.jwt.test;


import java.net.MalformedURLException;
import java.net.URL;

import com.nimbusds.jwt.Header;
import com.nimbusds.jwt.HeaderException;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWSHeader;

import junit.framework.TestCase;


/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-26)
 */
public class JWSHeaderTest extends TestCase {
	
	
	public void testParse() {
	
		// Example header from JWS spec
		
		String s = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
		
		JWSHeader h = null;
		
		try {
			h = JWSHeader.parse(s);
			
		} catch (HeaderException e) {
		
			fail(e.getMessage());
		}
		
		assertNotNull(h);
		
		assertEquals(Header.Type.JWT, h.getType());
		assertEquals(JWA.HS256, h.getAlgorithm());
	}
}
