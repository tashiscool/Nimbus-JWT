package com.nimbusds.jwt.test;


import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jwt.ClaimsSet;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.Header;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWEHeader;
import com.nimbusds.jwt.ReadOnlyJWEHeader;

import net.minidev.json.JSONObject;

import junit.framework.TestCase;


/**
 * Tests encrypted JWTs.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-26)
 */
public class EncryptedJWTTest extends TestCase {
	

	public void testConstructor() {

		JWEHeader h = new JWEHeader(JWA.RSA1_5);
		h.setType(Header.Type.JWT);
		h.setEncryptionMethod(JWA.A128CBC);

		JSONObject claims = new JSONObject();
		claims.put("iss", "http://nimbusds.com");
		claims.put("exp", 123);
		claims.put("act", true);

		EncryptedJWT jwt = new EncryptedJWT(h, new ClaimsSet(claims));
		
		assertNotNull(jwt.getHeader());
		assertNotNull(jwt.getClaimsSet());
		
		ReadOnlyJWEHeader hOut = jwt.getHeader();
		assertEquals(JWA.RSA1_5, hOut.getAlgorithm());
		assertEquals(JWA.A128CBC, hOut.getEncryptionMethod());
		assertEquals(Header.Type.JWT, hOut.getType());
		assertTrue(hOut.getCustomParameters().isEmpty());
		
		assertNull(jwt.getEncryptedKey());
		assertNull(jwt.getCipherText());
		
		assertEquals(EncryptedJWT.State.UNENCRYPTED, jwt.getState());
	}
}
