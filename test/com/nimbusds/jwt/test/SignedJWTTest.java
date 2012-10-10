package com.nimbusds.jwt.test;


import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jwt.ClaimsSet;
import com.nimbusds.jwt.Header;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWSException;
import com.nimbusds.jwt.JWSHeader;
import com.nimbusds.jwt.JWTException;
import com.nimbusds.jwt.ReadOnlyJWSHeader;
import com.nimbusds.jwt.SignedJWT;

import net.minidev.json.JSONObject;

import junit.framework.TestCase;


/**
 * Tests signed JWTs.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-26)
 */
public class SignedJWTTest extends TestCase {
	

	public void testConstructor() {

		JWSHeader h = new JWSHeader(JWA.HS256);
		h.setType(Header.Type.JWT);

		JSONObject claims = new JSONObject();
		claims.put("iss", "http://nimbusds.com");
		claims.put("exp", 123);
		claims.put("act", true);

		SignedJWT jwt = new SignedJWT(h, new ClaimsSet(claims));
		
		assertNotNull(jwt.getHeader());
		assertNotNull(jwt.getClaimsSet());
		
		ReadOnlyJWSHeader hOut = jwt.getHeader();
		assertEquals(JWA.HS256, hOut.getAlgorithm());
		assertEquals(Header.Type.JWT, hOut.getType());
		assertTrue(hOut.getCustomParameters().isEmpty());
		
		assertNull(jwt.getSignature());
		
		assertEquals(SignedJWT.State.UNSIGNED, jwt.getState());
	}
	public void testParse() throws JWTException, JWSException {

		String s = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJhdWQiOiAiR29vZ2xlIiwgImlzcyI6ICIxMDg3MzY2MDM1NDYyMDA5NDcxNiIsICJyZXF1ZXN0IjogeyJwcmljZSI6ICI5Ljk5IiwgImN1cnJlbmN5Q29kZSI6ICJVU0QiLCAic2VsbGVyRGF0YSI6ICIrZ29sZCwgK25vL2NvdXBvbi9kaXNjb3VudCIsICJuYW1lIjogIlZpcnR1YWwgR29sZCBNZWRhbCIsICJkZXNjcmlwdGlvbiI6ICJBIHZpcnR1YWwgZ29sZCBtZWRhbCBmcm9tIHRoZSAyMDEwIG9seW1waWMgZ2FtZXMgZm9yIG1lbidzIGZyZWVzdHlsZSBza2lpbmcuIn0sICJleHAiOiAxMzEyMjM5OTY1LCAiaWF0IjogMTMxMjIzOTM2NSwgInR5cCI6ICJnb29nbGUvcGF5bWVudHMvaW5hcHAvaXRlbS92MSJ9.t5tIXnc0vqG1cd7-59zu-egRRSUKC80kBCNq8Ukqe68";
		byte[] sharedSecret = "1234567890123456".getBytes();
		
		JWSHeader h = new JWSHeader(JWA.HS256);
		h.setType(Header.Type.JWT);

		JSONObject claims = new JSONObject();
		claims.put("iss", "http://nimbusds.com");
		claims.put("exp", 123);
		claims.put("act", true);

		SignedJWT jwt = SignedJWT.parse(s);
		
		assertNotNull(jwt.getHeader());
		assertNotNull(jwt.getClaimsSet());
		
		ReadOnlyJWSHeader hOut = jwt.getHeader();
		assertEquals(JWA.HS256, hOut.getAlgorithm());
		assertEquals(Header.Type.JWT, hOut.getType());
		jwt.hmacVerify(sharedSecret );
		assertEquals(SignedJWT.State.VERIFIED, jwt.getState());	
		
	}
}
