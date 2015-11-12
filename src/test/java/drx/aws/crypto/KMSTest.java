package drx.aws.crypto;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dave
 */
public class KMSTest {
  private String keyName = "unit-test";
  
  /**
   * Test of generateDataKey method, of class KMS.
   */
  @Test
  public void testGenerateDataKey() throws Exception {
    String result = KMS.generateDataKey(keyName);
    System.out.println("generateDataKey: "+result);
    assertTrue(result.length()>100);
  }

  /**
   * Test of encrypt method, of class KMS.
   */
  @Test
  public void testEncrypt() {
    String plaintextData = "This is plaintext data for unit testing";
    String encr = KMS.encrypt(plaintextData, keyName);
    String decr = KMS.decrypt(encr, keyName);
    assertEquals(plaintextData, decr);
    
    try {
      KMS.encrypt(null, keyName);
    } catch(Exception e) {
      assertTrue(e instanceof NullPointerException);
    }

    while(plaintextData.length()<5000) plaintextData += plaintextData;
    encr = KMS.encrypt(plaintextData, keyName);
    decr = KMS.decrypt(encr, keyName);
    assertEquals(plaintextData, decr);
  }
  
}
