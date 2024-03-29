/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at legal-notices/CDDLv1_0.txt
 * or http://forgerock.org/license/CDDLv1.0.html.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at legal-notices/CDDLv1_0.txt.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information:
 *      Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 *
 *      Copyright 2006-2008 Sun Microsystems, Inc.
 *      Portions Copyright 2012-2015 ForgeRock AS.
 *      Portions Copyrighted 2019 OGIS-RI Co., Ltd.
 */
package org.opends.dsml.protocol;



import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.forgerock.i18n.LocalizableMessage;
import org.forgerock.opendj.ldap.DecodeException;
import org.opends.server.protocols.ldap.AddRequestProtocolOp;
import org.opends.server.protocols.ldap.AddResponseProtocolOp;
import org.opends.server.protocols.ldap.LDAPAttribute;
import org.opends.server.protocols.ldap.LDAPMessage;
import org.opends.server.protocols.ldap.ProtocolOp;
import org.opends.server.tools.LDAPConnection;
import org.forgerock.opendj.ldap.ByteString;
import org.opends.server.types.LDAPException;
import org.opends.server.types.RawAttribute;



/**
 * This class provides the functionality for the performing an
 * LDAP ADD operation based on the specified DSML request.
 */
public class DSMLAddOperation
{

  private LDAPConnection connection;

  /**
   * Create the instance with the specified LDAP connection.
   *
   * @param connection     The LDAP connection to the server.
   */
  public DSMLAddOperation(LDAPConnection connection)
  {
    this.connection = connection;
  }

  /**
   * Perform the LDAP ADD operation and return the result to the client.
   *
   * @param  objFactory  The object factory for this operation.
   * @param  addRequest  The add request for this operation.
   * @param  controls    Any required controls (e.g. for proxy authz).
   *
   * @return  The result of the add operation.
   *
   * @throws  IOException  If an I/O problem occurs.
   *
   * @throws  LDAPException  If an error occurs while interacting with an LDAP
   *                         element.
   *
   * @throws  DecodeException  If an error occurs while interacting with an ASN.1
   *                         element.
   */
  public LDAPResult doOperation(ObjectFactory objFactory,
        AddRequest addRequest,
        List<org.opends.server.types.Control> controls)
    throws IOException, LDAPException, DecodeException
  {
    LDAPResult addResponse = objFactory.createLDAPResult();
    addResponse.setRequestID(addRequest.getRequestID());

    ByteString dnStr = ByteString.valueOfUtf8(addRequest.getDn());
    ArrayList<RawAttribute> attributes = new ArrayList<>();

    List<DsmlAttr> addList = addRequest.getAttr();
    for(DsmlAttr attr : addList)
    {
      ArrayList<ByteString> values = new ArrayList<>();
      List vals = attr.getValue();
      for(Object val : vals)
      {
        values.add(ByteStringUtility.convertValue(val));
      }
      LDAPAttribute ldapAttribute = new LDAPAttribute(attr.getName(), values);
      attributes.add(ldapAttribute);
    }

    // Create and send the LDAP request to the server.
    ProtocolOp op = new AddRequestProtocolOp(dnStr, attributes);
    LDAPMessage msg = new LDAPMessage(DSMLServlet.nextMessageID(), op,
        controls);
    connection.getLDAPWriter().writeMessage(msg);

    // Read and decode the LDAP response from the server.
    LDAPMessage responseMessage = connection.getLDAPReader().readMessage();

    AddResponseProtocolOp addOp = responseMessage.getAddResponseProtocolOp();
    int resultCode = addOp.getResultCode();
    LocalizableMessage errorMessage = addOp.getErrorMessage();

    // Set the result code and error message for the DSML response.
    addResponse.setErrorMessage(
            errorMessage != null ? errorMessage.toString() : null);
    ResultCode code = ResultCodeFactory.create(objFactory, resultCode);
    addResponse.setResultCode(code);

    return addResponse;
  }

}

