/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions Copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 3A Systems, LLC.
 */
package org.opends.server.protocols.jmx;

import static org.testng.Assert.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;


import org.opends.server.DirectoryServerTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/** Tests JMX RMI credential deserialization hardening. */
@Test(groups = { "precommit", "jmx" }, sequential = true)
public class RmiAuthenticatorTest extends DirectoryServerTestCase
{
  /** Invalid credential shapes rejected before any bind attempt. */
  @DataProvider(name = "invalidCredentials")
  public Object[][] invalidCredentials()
  {
    return new Object[][]
    {
      { null },
      { new Object[] { "cn=Directory Manager", "password" } },
      { new Date() },
      { new String[0] },
      { new String[] { "cn=Directory Manager" } },
      { new String[] { "cn=Directory Manager", "password", "extra" } },
      { new String[] { null, "password" } },
      { new String[] { "cn=Directory Manager", null } }
    };
  }

  /** Verifies that RmiAuthenticator only accepts a two-element String array. */
  @Test(dataProvider = "invalidCredentials", expectedExceptions = SecurityException.class)
  public void rejectsInvalidCredentialShapes(Object credentials)
  {
    new RmiAuthenticator(null).authenticate(credentials);
  }

  /** Verifies that RMI connector environment constrains credential unmarshalling. */
  @Test
  public void configuresCredentialDeserializationProtection()
  {
    Map<String, Object> env = new HashMap<>();
    RmiConnector.configureJmxDeserializationProtection(env);

    assertEquals(env.get(RmiConnector.JMX_REMOTE_RMI_SERVER_CREDENTIALS_FILTER_PATTERN),
        "maxdepth=3;maxarray=2;java.lang.String;!*");
    // The connector-wide filter is now also configured so that post-authentication
    // traffic (MBean operation arguments, attribute values) is constrained to a
    // safe allowlist instead of being deserialized without any filter
    // (CVE-2026-62373 / GHSA-qj63-3vrg-vcfx, incomplete fix of CVE-2026-46495).
    // Like the credentials filter, this jmx.remote.rmi.server.serial.filter.pattern
    // property is honoured only by the JDK 10+ RMIConnectorServer and is silently
    // ignored on a Java 8 runtime, so this asserts only the connector wiring, not
    // runtime enforcement. End-to-end enforcement is covered by the JMX
    // integration tests when running on a JDK 10+ runtime.
    assertNotNull(env.get(RmiConnector.JMX_REMOTE_RMI_SERVER_SERIAL_FILTER_PATTERN));
    // "jmx.remote.rmi.server.credential.types" is mutually exclusive with the
    // credentials filter pattern: setting both prevents the connector from
    // starting, so only the filter pattern must be configured.
    assertNull(env.get("jmx.remote.rmi.server.credential.types"));
  }

  // Note: the actual enforcement of these serial filters is performed by the
  // JDK's RMIConnectorServer (the "jmx.remote.rmi.server.credentials.filter.pattern"
  // and "jmx.remote.rmi.server.serial.filter.pattern" properties, available on
  // JDK 10+). A unit test exercising it directly would have to use
  // java.io.ObjectInputFilter / ObjectInputStream.setObjectInputFilter(),
  // which do not exist on Java 8 and would break compilation on a Java 8 build.
  // We therefore assert only the connector wiring (above) and the credential
  // shape validation performed by RmiAuthenticator (which works on all JDKs and
  // is itself a defense-in-depth check). End-to-end filter behaviour is covered
  // by the JMX integration tests when running on a JDK 9+ runtime.
}
