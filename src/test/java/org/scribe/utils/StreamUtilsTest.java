package org.scribe.utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import com.dotcms.repackage.org.junit.Test;

import static com.dotcms.repackage.org.junit.Assert.*;

public class StreamUtilsTest
{

  @Test
  public void shouldCorrectlyDecodeAStream()
  {
    String value = "expected";
    InputStream is = new ByteArrayInputStream(value.getBytes());
    String decoded = StreamUtils.getStreamContents(is);
    assertEquals("expected", decoded);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void shouldFailForNullParameter()
  {
    InputStream is = null;
    StreamUtils.getStreamContents(is);
    fail("Must throw exception before getting here");
  }
}
