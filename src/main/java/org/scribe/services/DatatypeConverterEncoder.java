package org.scribe.services;

import com.dotcms.repackage.javax.xml.bind.DatatypeConverter;

public class DatatypeConverterEncoder extends Base64Encoder
{
  @Override
  public String encode(byte[] bytes)
  {
    return DatatypeConverter.printBase64Binary(bytes);
  }

  @Override
  public String getType()
  {
    return "DatatypeConverter";
  }
}
