package com.nimbusds.jwt.test;


import com.nimbusds.jwt.CompressionAlgorithm;
import com.nimbusds.jwt.CompressionUtils;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWEHeader;

import junit.framework.TestCase;


/**
 * Tests JWE payload compression.
 *
 * @version $version$ (2012-05-21)
 */
public class CompressionUtilsTest extends TestCase {


	public void testNONE()
		throws Exception {
	
		final String text = "abc123";
		final byte[] textBytes = text.getBytes("UTF-8");
		
		JWEHeader header = new JWEHeader(JWA.A128GCM);
		header.setCompressionAlgorithm(CompressionAlgorithm.NONE);
	
		byte[] compressed = CompressionUtils.compressIfRequired(header, textBytes);
		assertTrue(compressed.length == textBytes.length);
		
		for (int i=0; i < textBytes.length; i++)
			assertEquals(textBytes[i], compressed[i]);
	}
	
	
	public void testNull()
		throws Exception {
	
		final String text = "abc123";
		final byte[] textBytes = text.getBytes("UTF-8");
		
		JWEHeader header = new JWEHeader(JWA.A128GCM);
		header.setCompressionAlgorithm(null);
	
		byte[] compressed = CompressionUtils.compressIfRequired(header, textBytes);
		assertTrue(compressed.length == textBytes.length);
		
		for (int i=0; i < textBytes.length; i++)
			assertEquals(textBytes[i], compressed[i]);
	}
	
	
	public void testGZIP()
		throws Exception {
	
		final String text = "abc123";
		final byte[] textBytes = text.getBytes("UTF-8");
		
		JWEHeader header = new JWEHeader(JWA.A128GCM);
		header.setCompressionAlgorithm(CompressionAlgorithm.DEF);
	
		byte[] compressed = CompressionUtils.compressIfRequired(header, textBytes);
		assertTrue(compressed.length > textBytes.length);
		
		byte[] textBytesDecompressed = CompressionUtils.decompressIfRequired(header, compressed);
		String textDecompressed = new String(textBytesDecompressed, "UTF-8");
		
		assertEquals(text.length(), textDecompressed.length());
		assertEquals(text, textDecompressed);
	}
}
