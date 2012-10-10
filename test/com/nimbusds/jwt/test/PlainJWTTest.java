package com.nimbusds.jwt.test;


import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jwt.ClaimsSet;
import com.nimbusds.jwt.Header;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWTException;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.ReadOnlyPlainJWTHeader;

import net.minidev.json.JSONObject;

import junit.framework.TestCase;


/**
 * Tests plain JWT parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-26)
 */
public class PlainJWTTest extends TestCase {
	

	public void testSerializeAndParse() {

		JSONObject claims = new JSONObject();
		claims.put("iss", "http://nimbusds.com");
		claims.put("exp", 123);
		claims.put("act", true);

		PlainJWT jwt = new PlainJWT(new ClaimsSet(claims));
		
		assertNotNull(jwt.getHeader());
		assertNotNull(jwt.getClaimsSet());
		
		ReadOnlyPlainJWTHeader h = jwt.getHeader();
		assertEquals(JWA.NONE, h.getAlgorithm());
		assertEquals(Header.Type.JWT, h.getType());
		assertTrue(h.getCustomParameters().isEmpty());
		
		
		String s = jwt.serialize();
		
		try {
			jwt = PlainJWT.parse(s);
			
		} catch (JWTException e) {
		
			fail(e.getMessage());
		}
		
		h = jwt.getHeader();
		assertEquals(JWA.NONE, h.getAlgorithm());
		assertEquals(Header.Type.JWT, h.getType());
		assertTrue(h.getCustomParameters().isEmpty());
		
		claims = jwt.getClaimsSet().toJSONObject();
		assertNotNull(claims);
		assertEquals("http://nimbusds.com", (String)claims.get("iss"));
		assertEquals(123, new Integer((Integer)claims.get("exp")).intValue());
		assertTrue((Boolean)claims.get("act"));
	}
}
