/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keyczar;


import java.io.RandomAccessFile;
import java.util.Arrays;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.keyczar.exceptions.KeyNotFoundException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.ShortCiphertextException;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Clock;

/**
 * Tests for every wire format across platforms 
 *
 * @author jay+code@tuely.name (Jay Tuley)
 */

public abstract class InteropTest extends TestCase {
  private static final Logger LOG = Logger.getLogger(InteropTest.class);
  private static final String TEST_DATA = "./interop-data";
  private String input = "This is some test data";
  protected String platform;
  
  private final void testDecrypt(String subDir) throws Exception {
    testDecrypt(new KeyczarFileReader(testData(subDir)), subDir);
  }
  
  private String testData(String subDir){
	  return TEST_DATA + "/"+ platform + "_data" + subDir;
  }

  private final void testDecrypt(KeyczarReader reader, String subDir)
      throws Exception {
    Crypter crypter = new Crypter(reader);
    RandomAccessFile activeInput =
      new RandomAccessFile(testData(subDir) + "/1.out", "r");
    String activeCiphertext = activeInput.readLine(); 
    activeInput.close();
    RandomAccessFile primaryInput =
      new RandomAccessFile(testData(subDir) + "/2.out", "r");
    String primaryCiphertext = primaryInput.readLine();
    primaryInput.close();
    String activeDecrypted = crypter.decrypt(activeCiphertext);
    assertEquals(input, activeDecrypted);
    String primaryDecrypted = crypter.decrypt(primaryCiphertext);
    assertEquals(input, primaryDecrypted);
  }
  
  private final void testDecryptSize(String subDir, String size)
	      throws Exception {
	    Crypter crypter = new Crypter(testData(subDir+ "-size"));
	    RandomAccessFile activeInput =
	      new RandomAccessFile(testData(subDir) + "-size/"+size +".out", "r");
	    String activeCiphertext = activeInput.readLine(); 
	    activeInput.close();
	    String activeDecrypted = crypter.decrypt(activeCiphertext);
	    assertEquals(input, activeDecrypted);
	  }
  
  @Test
  public final void testAesDecrypt() throws Exception {
    testDecrypt("/aes");
  }
  
  @Test 
  public final void testAesDecrypt128() throws Exception {
	  testDecryptSize("/aes", "128");
  }
  
  @Test 
  public final void testAesDecrypt192() throws Exception {
	  testDecryptSize("/aes", "192");
  }
  
  @Test 
  public final void testAesDecrypt256() throws Exception {
	  testDecryptSize("/aes", "256");
  }
  
  
  @Test
  public final void testRsaDecrypt() throws Exception  {
    testDecrypt("/rsa");
  }
  
  @Test 
  public final void testRsaDecrypt1024() throws Exception {
	  testDecryptSize("/rsa", "1024");
  }
  
  @Test 
  public final void testRsaDecrypt2048() throws Exception {
	  testDecryptSize("/rsa", "2048");
  }
  
  @Test 
  public final void testRsaDecrypt4096() throws Exception {
	  testDecryptSize("/rsa", "4096");
  }

  
  @Test 
  public final void testAesEncryptedKeyDecrypt() throws Exception {
    // Test reading and using encrypted keys
    KeyczarFileReader fileReader =
      new KeyczarFileReader(testData("/aes-crypted"));
    Crypter keyDecrypter = new Crypter(testData("/aes"));
    KeyczarEncryptedReader reader =
      new KeyczarEncryptedReader(fileReader, keyDecrypter);
    testDecrypt(reader, "/aes-crypted");
  }
  

  private final void testVerify(String subDir) throws Exception {
	    Verifier verifier = new Verifier(testData(subDir));
	    RandomAccessFile activeInput =
	      new RandomAccessFile(testData(subDir) + "/1.out", "r");
	    String activeSignature = activeInput.readLine(); 
	    activeInput.close();
	    RandomAccessFile primaryInput =
	      new RandomAccessFile(testData(subDir) + "/2.out", "r");
	    String primarySignature = primaryInput.readLine();
	    primaryInput.close();

	    assertTrue(verifier.verify(input, activeSignature));
	    assertTrue(verifier.verify(input, primarySignature));
	}
	
	private final void testVerifyUnversioned(String subDir) throws Exception {
		UnversionedVerifier verifier = new UnversionedVerifier(testData(subDir));
	    RandomAccessFile activeInput =
	      new RandomAccessFile(testData(subDir) + "/2.unversioned", "r");
	    String activeSignature = activeInput.readLine(); 
	    activeInput.close();
	    assertTrue(verifier.verify(input, activeSignature));
	  }
	
	private final void testVerifyAttached(String subDir,String hidden) throws Exception {
		Verifier verifier = new Verifier(testData(subDir));
		String hiddenExt="";
		if(hidden != "")
			hiddenExt = "." + hidden;
	    RandomAccessFile activeInput =
	      new RandomAccessFile(testData(subDir) + "/2"+hiddenExt+".attached", "r");
	    String activeSignature = activeInput.readLine(); 
	    activeInput.close();
	    assertTrue(verifier.attachedVerify(Base64Coder.decodeWebSafe(activeSignature), 
	    		hidden.getBytes(Keyczar.DEFAULT_ENCODING)));
	  }
	
	private final void testVerifySize(String subDir, String size) throws Exception {
		Verifier verifier = new Verifier(testData(subDir+ "-size"));
	    RandomAccessFile activeInput =
	      new RandomAccessFile(testData(subDir) + "-size/"+ size +".out", "r");
	    String activeSignature = activeInput.readLine(); 
	    activeInput.close();
	    assertTrue(verifier.verify(input, activeSignature));
	  }
	
	  @Test 
	  public final void testHmacVerify() throws Exception {
		  testVerify("/hmac");
	  }
	  
	  @Test 
	  public final void testHmacVerifyUnversioned() throws Exception {
		  testVerifyUnversioned("/hmac");
	  }
	  
	  @Test 
	  public final void testHmacVerifyAttached() throws Exception {
		  testVerifyAttached("/hmac","");
	  }
	  
	  @Test 
	  public final void testHmacVerifyAttachedSecret() throws Exception {
		  testVerifyAttached("/hmac","secret");
	  }
	
	  @Test 
	  public final void testDsaVerify() throws Exception {
		  testVerify("/dsa");
	  }
	  
	  @Test 
	  public final void testDsaVerifyUnversioned() throws Exception {
		  testVerifyUnversioned("/dsa");
	  }
	
	  @Test 
	  public final void testDsaVerifyAttached() throws Exception {
		  testVerifyAttached("/dsa","");
	  }
	  
	  @Test 
	  public final void testDsaVerifyAttachedSecret() throws Exception {
		  testVerifyAttached("/dsa","secret");
	  }
	  
	  @Test 
	  public final void testRsaVerify() throws Exception {
		  testVerify("/rsa-sign");
	  }
	  
	  @Test 
	  public final void testRsaVerifyAttached() throws Exception {
		  testVerifyAttached("/rsa-sign","");
	  }
	  
	  @Test 
	  public final void testRsaVerifyAttachedSecret() throws Exception {
		  testVerifyAttached("/rsa-sign","secret");
	  }

	  
	  @Test 
	  public final void testRsaVerifyUnversioned() throws Exception {
		  testVerifyUnversioned("/rsa-sign");
	  }
	
	  
	  @Test 
	  public final void testRsaVerify1024() throws Exception {
		  testVerifySize("/rsa-sign","1024");
	  }
	  
	  @Test 
	  public final void testRsaVerify2048() throws Exception {
		  testVerifySize("/rsa-sign","2048");
	  }
	  
	  @Test 
	  public final void testRsaVerify4096() throws Exception {
		  testVerifySize("/rsa-sign","4096");
	  }
	  

	  private final void testSessionDecrypt(String subDir) throws Exception {
		    RandomAccessFile activeInput =
		      new RandomAccessFile(testData(subDir) + "/2.session.material", "r");
		    String sessionMaterial = activeInput.readLine(); 
		    activeInput.close();
		    
		    SessionCrypter crypter = new SessionCrypter(new Crypter(testData(subDir)),
		    		Base64Coder.decodeWebSafe(sessionMaterial));

		    RandomAccessFile primaryInput =
		      new RandomAccessFile(testData(subDir) + "/2.session.ciphertext", "r");
		    String activeCiphertext = primaryInput.readLine();
		    primaryInput.close();

		    byte[] activeDecrypted = crypter.decrypt(Base64Coder.decodeWebSafe(activeCiphertext));
		    assertEquals(input, new String(activeDecrypted, Keyczar.DEFAULT_ENCODING));
		  }
	  
	  @Test 
	  public final void testRsaSessionDecrypt() throws Exception {
		  testSessionDecrypt("/rsa");
	  }
	  
	  private final void testSignedSessionDecrypt(String subDir, String verifierDir) throws Exception {

		    RandomAccessFile activeInput =
		      new RandomAccessFile(testData(subDir) + "/2.signedsession.material", "r");
		    String sessionMaterial = activeInput.readLine(); 
		    activeInput.close();
		    
		    SignedSessionDecrypter crypter = new SignedSessionDecrypter(new Crypter(testData(subDir)),
		    		new Verifier(testData(verifierDir)),
		    		sessionMaterial);

		    RandomAccessFile primaryInput =
		      new RandomAccessFile(testData(subDir) + "/2.signedsession.ciphertext", "r");
		    String activeCiphertext = primaryInput.readLine();
		    primaryInput.close();

		    byte[] activeDecrypted = crypter.decrypt(Base64Coder.decodeWebSafe(activeCiphertext));
		    assertEquals(input, new String(activeDecrypted, Keyczar.DEFAULT_ENCODING));
		  }
	  @Test 
	  public final void testRsaDsaSignedSessionDecrypt() throws Exception {
		  testSignedSessionDecrypt("/rsa", "/dsa.public");
	  }
	  
	  public class EarlyClock implements Clock{
		  public long now(){
			  return 1356087960000L;
		  }
	  }
	  
	  public class LateClock implements Clock{
		  public long now(){
			  return 1356088560000L;
		  }
	  }
	  
	  private final void testTimeoutVerifier(String subDir) throws Exception {
			TimeoutVerifier verifier = new TimeoutVerifier(testData(subDir));
			verifier.setClock(new EarlyClock());
		    RandomAccessFile activeInput =
		      new RandomAccessFile(testData(subDir) + "/2.timeout", "r");
		    String activeSignature = activeInput.readLine(); 
		    activeInput.close();
		    assertTrue(verifier.verify(input, activeSignature));
	  }
	  
      private final void testTimeoutVerifierExpired(String subDir) throws Exception {
    		TimeoutVerifier verifier = new TimeoutVerifier(testData(subDir));
			verifier.setClock(new LateClock());
		    RandomAccessFile activeInput =
		      new RandomAccessFile(testData(subDir) + "/2.timeout", "r");
		    String activeSignature = activeInput.readLine(); 
		    activeInput.close();
		    assertFalse(verifier.verify(input, activeSignature));
	  }
      
	  @Test 
	  public final void testHmacTimeoutVerifier() throws Exception {
		  testTimeoutVerifier("/hmac");
	  }
	  
	  @Test 
	  public final void testHmacTimeoutVerifierExpired() throws Exception {
		  testTimeoutVerifierExpired("/hmac");
	  }
	  
	  
	  @Test 
	  public final void testDsaTimeoutVerifier() throws Exception {
		  testTimeoutVerifier("/dsa");
	  }
	  
	  @Test 
	  public final void testDsaTimeoutVerifierExpired() throws Exception {
		  testTimeoutVerifierExpired("/dsa");
	  }
	  
	  @Test 
	  public final void testRsaTimeoutVerifier() throws Exception {
		  testTimeoutVerifier("/rsa-sign");
	  }
	  
	  @Test 
	  public final void testRsaTimeoutVerifierExpired() throws Exception {
		  testTimeoutVerifierExpired("/rsa-sign");
	  }
}