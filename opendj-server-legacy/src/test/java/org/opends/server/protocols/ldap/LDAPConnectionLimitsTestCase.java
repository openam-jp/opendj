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
 * Portions Copyright 2026 OSSTech Corporation
 */
package org.opends.server.protocols.ldap;

import static org.mockito.Mockito.mock;
import static org.opends.messages.ProtocolMessages.*;
import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.forgerock.i18n.LocalizableMessage;
import org.opends.server.TestCaseUtils;
import org.opends.server.admin.DefinedDefaultBehaviorProvider;
import org.opends.server.admin.PropertyDefinition;
import org.opends.server.admin.std.meta.GlobalCfgDefn;
import org.opends.server.admin.std.server.LDAPConnectionHandlerCfg;
import org.opends.server.api.ClientConnection;
import org.opends.server.api.ConnectionHandler;
import org.opends.server.api.plugin.InternalDirectoryServerPlugin;
import org.opends.server.api.plugin.PluginResult;
import org.opends.server.api.plugin.PluginType;
import org.opends.server.core.DirectoryServer;
import org.opends.server.core.ServerContext;
import org.opends.server.tools.LDAPReader;
import org.opends.server.types.DN;
import org.opends.server.types.DisconnectReason;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Regression test for GHSA-7778-jm7p-68g5: the LDAP listener let unauthenticated clients hold connections until the
 * server stopped accepting new ones. A connection handler now closes a connection on which no complete request
 * arrives within {@code first-request-time-limit}, limits the connections from one client address with
 * {@code max-client-connections-per-address}, and the server-wide {@code max-allowed-client-connections} never
 * rejects a connection to the administration connector.
 */
@SuppressWarnings("javadoc")
@Test(groups = { "precommit", "ldap" }, sequential = true)
public class LDAPConnectionLimitsTestCase extends LdapTestCase
{
  private static final LocalizableMessage STOP_REASON = LocalizableMessage.raw("Stopped by the limits test.");
  private static final String NOTICE_OF_DISCONNECTION_OID = "1.3.6.1.4.1.1466.20036";
  private static final long TIMEOUT_MS = 10000;
  /** How long a connection which must stay open is watched. */
  private static final int STAYS_OPEN_MS = 2500;
  private static final long FIRST_REQUEST_TIME_LIMIT_MS = 1000;
  /** An anonymous simple bind request, message ID 1. */
  private static final byte[] ANONYMOUS_BIND = {
    0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, (byte) 0x80, 0x00 };

  @BeforeClass
  public void setUp() throws Exception
  {
    TestCaseUtils.startServer();
  }

  @Test
  public void silentConnectionIsClosedOnceTheFirstRequestTimeLimitIsSpent() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler = start(configuration(port, "ds-cfg-first-request-time-limit: 1 seconds"));
    try (Socket client = new Socket("127.0.0.1", port))
    {
      final long connected = System.currentTimeMillis();
      assertNoticeOfDisconnection(
          client, INFO_CONNHANDLER_FIRST_REQUEST_TIME_LIMIT_EXCEEDED.get(FIRST_REQUEST_TIME_LIMIT_MS));
      assertTrue(System.currentTimeMillis() - connected >= FIRST_REQUEST_TIME_LIMIT_MS - 100,
          "the connection was closed before the limit was spent");
      awaitClientConnections(handler, 0);
    }
    finally
    {
      stop(handler);
    }
  }

  @Test
  public void partOfARequestIsNotAFirstRequest() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler = start(configuration(port, "ds-cfg-first-request-time-limit: 1 seconds"));
    try (Socket client = new Socket("127.0.0.1", port))
    {
      final OutputStream out = client.getOutputStream();
      out.write(ANONYMOUS_BIND, 0, ANONYMOUS_BIND.length - 3);
      out.flush();
      assertNoticeOfDisconnection(
          client, INFO_CONNHANDLER_FIRST_REQUEST_TIME_LIMIT_EXCEEDED.get(FIRST_REQUEST_TIME_LIMIT_MS));
    }
    finally
    {
      stop(handler);
    }
  }

  @Test
  public void connectionWhichSentARequestOutlivesTheFirstRequestTimeLimit() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler = start(configuration(port, "ds-cfg-first-request-time-limit: 1 seconds"));
    try (Socket client = new Socket("127.0.0.1", port))
    {
      bindAnonymously(client);
      assertStaysOpen(client);
      assertEquals(handler.getClientConnections().size(), 1);
    }
    finally
    {
      stop(handler);
    }
  }

  @Test
  public void zeroFirstRequestTimeLimitKeepsASilentConnection() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler = start(configuration(port, "ds-cfg-first-request-time-limit: 0 seconds"));
    try (Socket client = new Socket("127.0.0.1", port))
    {
      awaitClientConnections(handler, 1);
      assertStaysOpen(client);
    }
    finally
    {
      stop(handler);
    }
  }

  /**
   * A first request time limit still pending when the handler is finalized must not keep its finalizer, which the
   * server shutdown waits for, alive until the limit is spent.
   */
  @Test
  public void pendingFirstRequestTimeLimitDoesNotOutliveTheHandler() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler = start(configuration(port, "ds-cfg-first-request-time-limit: 60 seconds"));
    final ExecutorService finalizer = finalizer(handler);
    try (Socket client = new Socket("127.0.0.1", port))
    {
      awaitClientConnections(handler, 1);
      stop(handler);
      assertTrue(finalizer.awaitTermination(TIMEOUT_MS, TimeUnit.MILLISECONDS),
          "the finalizer waits for the first request time limit");
    }
    finally
    {
      stop(handler);
    }
  }

  @Test
  public void handlerLimitsDefaultToAMinuteForTheFirstRequestAnd1024ConnectionsPerAddress() throws Exception
  {
    final LDAPConnectionHandlerCfg config = configuration(TestCaseUtils.findFreePort());
    assertEquals(config.getFirstRequestTimeLimit(), 60000L);
    assertEquals(config.getMaxClientConnectionsPerAddress(), 1024);
  }

  /**
   * The administration connector is not bounded by max-allowed-client-connections, so its own limits are what keep a
   * client from holding it.
   */
  @Test
  public void administrationConnectorLimitsAMinuteForTheFirstRequestAnd1024ConnectionsPerAddress() throws Exception
  {
    final LDAPConnectionHandlerCfg config = currentConfig(administrationConnectionHandler());
    assertEquals(config.getFirstRequestTimeLimit(), 60000L);
    assertEquals(config.getMaxClientConnectionsPerAddress(), 1024);
  }

  @Test
  public void connectionBeyondTheLimitOfItsAddressIsRejected() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler =
        start(configuration(port, "ds-cfg-max-client-connections-per-address: 2"));
    try (Socket first = new Socket("127.0.0.1", port);
        Socket second = new Socket("127.0.0.1", port))
    {
      awaitClientConnections(handler, 2);
      try (Socket third = new Socket("127.0.0.1", port))
      {
        assertNoticeOfDisconnection(third, ERR_CONNHANDLER_CLIENT_ADDRESS_LIMIT_REACHED.get(
            "127.0.0.1:" + third.getLocalPort(), "127.0.0.1:" + port, 2));
      }
      assertEquals(handler.getClientConnections().size(), 2);
      assertStaysOpen(first);
    }
    finally
    {
      stop(handler);
    }
  }

  @Test
  public void closedConnectionGivesBackItsPlaceToItsAddress() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler =
        start(configuration(port, "ds-cfg-max-client-connections-per-address: 2"));
    try (Socket first = new Socket("127.0.0.1", port))
    {
      try (Socket second = new Socket("127.0.0.1", port))
      {
        awaitClientConnections(handler, 2);
      }
      awaitClientConnections(handler, 1);
      awaitPlacesHeld(handler, 1);
      try (Socket third = new Socket("127.0.0.1", port))
      {
        awaitClientConnections(handler, 2);
        bindAnonymously(third);
      }
    }
    finally
    {
      stop(handler);
    }
  }

  @Test
  public void rejectedConnectionDoesNotTakeAPlaceOfItsAddress() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler =
        start(configuration(port, "ds-cfg-max-client-connections-per-address: 1"));
    try
    {
      try (Socket first = new Socket("127.0.0.1", port))
      {
        awaitClientConnections(handler, 1);
        for (int i = 0; i < 3; i++)
        {
          try (Socket rejected = new Socket("127.0.0.1", port))
          {
            rejected.setSoTimeout((int) TIMEOUT_MS);
            assertNotNull(new LDAPReader(rejected).readMessage(), "the rejected connection got no notice");
          }
        }
      }
      // Only the first connection held a place: once it is closed, a new one is accepted.
      awaitClientConnections(handler, 0);
      awaitPlacesHeld(handler, 0);
      try (Socket next = new Socket("127.0.0.1", port))
      {
        bindAnonymously(next);
      }
    }
    finally
    {
      stop(handler);
    }
  }

  /** A connection which takes a place and is then rejected by a post-connect plugin gives the place back. */
  @Test
  public void connectionRejectedAfterTakingAPlaceGivesItBack() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler =
        start(configuration(port, "ds-cfg-max-client-connections-per-address: 1"));
    final LocalizableMessage rejection = LocalizableMessage.raw("Rejected by the limits test plugin.");
    final RejectingPostConnectPlugin plugin = new RejectingPostConnectPlugin(handler, rejection);
    DirectoryServer.registerInternalPlugin(plugin);
    try
    {
      for (int i = 0; i < 2; i++)
      {
        try (Socket rejected = new Socket("127.0.0.1", port))
        {
          assertNoticeOfDisconnection(rejected, rejection);
        }
        awaitPlacesHeld(handler, 0);
      }
    }
    finally
    {
      DirectoryServer.deregisterInternalPlugin(plugin);
      stop(handler);
    }
  }

  /**
   * An error, not only an exception, thrown once the connection took its place gives the place back. The error ends
   * the listener thread of the handler and leaves the connection open, as it did before the limit existed: the test
   * only checks the place, then cleans up the connection and the handler itself.
   */
  @Test
  public void connectionFailingWithAnErrorGivesBackItsPlace() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler =
        start(configuration(port, "ds-cfg-max-client-connections-per-address: 1"));
    final ThrowingPostConnectPlugin plugin = new ThrowingPostConnectPlugin(handler);
    DirectoryServer.registerInternalPlugin(plugin);
    try (Socket failed = new Socket("127.0.0.1", port))
    {
      // The connection takes its place before the plugin throws: wait for the plugin first, so that no place held
      // means the place was given back.
      final long deadline = System.currentTimeMillis() + TIMEOUT_MS;
      while (plugin.connection == null)
      {
        assertTrue(System.currentTimeMillis() < deadline, "the plugin saw no connection");
        Thread.sleep(50);
      }
      awaitPlacesHeld(handler, 0);
    }
    finally
    {
      DirectoryServer.deregisterInternalPlugin(plugin);
      if (plugin.connection != null)
      {
        plugin.connection.disconnect(DisconnectReason.OTHER, false, null);
      }
      handler.join(TIMEOUT_MS);
      handler.processServerShutdown(STOP_REASON);
      handler.finalizeConnectionHandler(STOP_REASON);
    }
  }

  /**
   * On a handler which uses SSL, a connection which sends nothing has not taken part in the TLS handshake: ending it
   * must not wait for the handshake, or the single finalizer thread of the handler hangs and times no other
   * connection. Both connections are closed in time only if the first one left the finalizer running.
   */
  @Test
  public void silentSslConnectionsAreClosedWithoutStoppingTheFinalizer() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler = start(sslConfiguration(port, "ds-cfg-first-request-time-limit: 1 seconds"));
    try
    {
      for (int i = 0; i < 2; i++)
      {
        try (Socket silent = new Socket("127.0.0.1", port))
        {
          assertClosedByServer(silent);
        }
      }
      awaitClientConnections(handler, 0);
    }
    finally
    {
      stop(handler);
    }
  }

  /**
   * On a handler which uses SSL, a connection rejected as it is accepted has not taken part in the TLS handshake:
   * rejecting it must not wait for the handshake, or the listener thread of the handler hangs and accepts no other
   * connection.
   */
  @Test
  public void sslConnectionRejectedBeyondTheLimitOfItsAddressDoesNotStopTheListener() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler = start(sslConfiguration(port,
        "ds-cfg-max-client-connections-per-address: 1", "ds-cfg-first-request-time-limit: 0 seconds"));
    try
    {
      try (Socket first = new Socket("127.0.0.1", port))
      {
        awaitClientConnections(handler, 1);
        try (Socket rejected = new Socket("127.0.0.1", port))
        {
          assertClosedByServer(rejected);
        }
      }
      awaitClientConnections(handler, 0);
      awaitPlacesHeld(handler, 0);
      // The listener accepts and registers the next connection. No TLS handshake is made: the test certificate,
      // signed with MD5withRSA, is refused by the algorithm constraints of recent JDKs.
      try (Socket next = new Socket("127.0.0.1", port))
      {
        awaitClientConnections(handler, 1);
        awaitPlacesHeld(handler, 1);
      }
      awaitClientConnections(handler, 0);
    }
    finally
    {
      stop(handler);
    }
  }

  @Test
  public void zeroLimitPerAddressAcceptsEveryConnection() throws Exception
  {
    final int port = TestCaseUtils.findFreePort();
    final LDAPConnectionHandler handler =
        start(configuration(port, "ds-cfg-max-client-connections-per-address: 0"));
    final List<Socket> clients = new ArrayList<>();
    try
    {
      for (int i = 0; i < 5; i++)
      {
        clients.add(new Socket("127.0.0.1", port));
      }
      awaitClientConnections(handler, clients.size());
      for (Socket client : clients)
      {
        bindAnonymously(client);
      }
    }
    finally
    {
      for (Socket client : clients)
      {
        client.close();
      }
      stop(handler);
    }
  }

  /**
   * Once the regular connections reach max-allowed-client-connections, the administrator must still be able to
   * connect to the administration connector, or nothing short of a restart can raise the limit.
   */
  @Test
  public void administrationConnectorIsReachableWhenTheConnectionLimitIsReached() throws Exception
  {
    final List<Socket> clients = new ArrayList<>();
    // The limit the server runs with, 0 when it has none, to set back afterwards.
    final long configured = Math.max(DirectoryServer.getMaxAllowedConnections(), 0);
    final long before = DirectoryServer.getCurrentConnections();
    final long limit = before + 3;
    TestCaseUtils.dsconfig("set-global-configuration-prop", "--set", "max-allowed-client-connections:" + limit);
    try
    {
      // The connection of dsconfig, like any connection still closing, is uncounted asynchronously: fill the limit
      // only once it is gone, or its uncounting would leave a place for the connection which must be rejected.
      awaitCurrentConnectionsAtMost(before);
      while (DirectoryServer.getCurrentConnections() < limit)
      {
        final Socket client = new Socket("127.0.0.1", TestCaseUtils.getServerLdapPort());
        clients.add(client);
        bindAnonymously(client);
      }
      try (Socket rejected = new Socket("127.0.0.1", TestCaseUtils.getServerLdapPort()))
      {
        rejected.setSoTimeout((int) TIMEOUT_MS);
        final LDAPMessage notice = new LDAPReader(rejected).readMessage();
        assertNotNull(notice, "the connection beyond the limit got no notice");
        assertEquals(notice.getExtendedResponseProtocolOp().getOID(), NOTICE_OF_DISCONNECTION_OID,
            "the regular connections did not reach the limit");
      }

      try (SSLSocket admin = (SSLSocket) trustAll().getSocketFactory().createSocket(
          "127.0.0.1", TestCaseUtils.getServerAdminPort()))
      {
        admin.startHandshake();
        bindAnonymously(admin);
        // Exempt from the limit, but counted.
        assertEquals(DirectoryServer.getCurrentConnections(), limit + 1, "connections counted with the administrator's");
      }
      catch (IOException e)
      {
        fail("the administration connector refused the connection once the limit was reached", e);
      }
    }
    finally
    {
      for (Socket client : clients)
      {
        client.close();
      }
      final long deadline = System.currentTimeMillis() + TIMEOUT_MS;
      while (DirectoryServer.getCurrentConnections() >= limit && System.currentTimeMillis() < deadline)
      {
        Thread.sleep(50);
      }
      TestCaseUtils.dsconfig("set-global-configuration-prop", "--set", "max-allowed-client-connections:" + configured);
    }
  }

  /**
   * Unlike upstream, the idle time is not limited by default: OpenAM, the main user of this server as its embedded
   * directory server, keeps pooled connections to it with neither heartbeat nor idle timeout by default.
   */
  @Test
  public void newServerLimitsTheConnectionsButNotTheirIdleTime() throws Exception
  {
    final File template = new File(TestCaseUtils.getBuildRoot(), "resource/config/config.ldif");
    final List<String> lines = Files.readAllLines(template.toPath(), StandardCharsets.UTF_8);
    assertTrue(lines.contains("ds-cfg-max-allowed-client-connections: 4096"),
        "max-allowed-client-connections of " + template);
    assertTrue(lines.contains("ds-cfg-idle-time-limit: 0 seconds"), "idle-time-limit of " + template);
  }

  /** A server without a value, for example after {@code dsconfig --reset}, falls back to the same limits. */
  @Test
  public void serverWithoutAValueLimitsTheConnectionsButNotTheirIdleTime() throws Exception
  {
    final GlobalCfgDefn global = GlobalCfgDefn.getInstance();
    assertEquals(defaultValues(global.getMaxAllowedClientConnectionsPropertyDefinition()), Arrays.asList("4096"));
    assertEquals(defaultValues(global.getIdleTimeLimitPropertyDefinition()), Arrays.asList("0 seconds"));
  }

  private static List<String> defaultValues(PropertyDefinition<?> property)
  {
    return new ArrayList<>(((DefinedDefaultBehaviorProvider<?>) property.getDefaultBehaviorProvider())
        .getDefaultValues());
  }

  /** Rejects every connection to the given handler once it is accepted. */
  private static final class RejectingPostConnectPlugin extends InternalDirectoryServerPlugin
  {
    private final LDAPConnectionHandler handler;
    private final LocalizableMessage rejection;

    private RejectingPostConnectPlugin(LDAPConnectionHandler handler, LocalizableMessage rejection)
        throws Exception
    {
      super(DN.valueOf("cn=Limits Test Post Connect Plugin"), EnumSet.of(PluginType.POST_CONNECT), false);
      this.handler = handler;
      this.rejection = rejection;
    }

    @Override
    public PluginResult.PostConnect doPostConnect(ClientConnection clientConnection)
    {
      if (clientConnection.getConnectionHandler() == handler)
      {
        return PluginResult.PostConnect.disconnectClient(DisconnectReason.CLOSED_BY_PLUGIN, true, rejection);
      }
      return PluginResult.PostConnect.continueConnectProcessing();
    }
  }

  /** Throws an error from the post-connect phase of the first connection to the given handler. */
  private static final class ThrowingPostConnectPlugin extends InternalDirectoryServerPlugin
  {
    private final LDAPConnectionHandler handler;
    private volatile ClientConnection connection;

    private ThrowingPostConnectPlugin(LDAPConnectionHandler handler) throws Exception
    {
      super(DN.valueOf("cn=Limits Test Throwing Plugin"), EnumSet.of(PluginType.POST_CONNECT), false);
      this.handler = handler;
    }

    @Override
    public PluginResult.PostConnect doPostConnect(ClientConnection clientConnection)
    {
      if (clientConnection.getConnectionHandler() == handler && connection == null)
      {
        connection = clientConnection;
        throw new NoClassDefFoundError("Thrown by the limits test plugin.");
      }
      return PluginResult.PostConnect.continueConnectProcessing();
    }
  }

  private static LDAPConnectionHandler administrationConnectionHandler()
  {
    for (ConnectionHandler<?> handler : DirectoryServer.getConnectionHandlers())
    {
      if (handler.isAdminConnectionHandler())
      {
        return (LDAPConnectionHandler) handler;
      }
    }
    throw new AssertionError("no administration connector");
  }

  private static LDAPConnectionHandlerCfg currentConfig(LDAPConnectionHandler handler) throws Exception
  {
    final Field field = LDAPConnectionHandler.class.getDeclaredField("currentConfig");
    field.setAccessible(true);
    return (LDAPConnectionHandlerCfg) field.get(handler);
  }

  private static ExecutorService finalizer(LDAPConnectionHandler handler) throws Exception
  {
    final Field field = LDAPConnectionHandler.class.getDeclaredField("connectionFinalizer");
    field.setAccessible(true);
    return (ExecutorService) field.get(handler);
  }

  /** Waits until the addresses of the clients hold the given number of places in all. */
  private static void awaitPlacesHeld(LDAPConnectionHandler handler, int expected) throws Exception
  {
    final Field field = LDAPConnectionHandler.class.getDeclaredField("connectionsPerAddress");
    field.setAccessible(true);
    final Map<?, ?> connectionsPerAddress = (Map<?, ?>) field.get(handler);
    final long deadline = System.currentTimeMillis() + TIMEOUT_MS;
    while (connectionsPerAddress.values().stream().mapToInt(held -> (Integer) held).sum() != expected)
    {
      assertTrue(System.currentTimeMillis() < deadline,
          "places held: " + connectionsPerAddress + ", not " + expected + " in all");
      Thread.sleep(50);
    }
  }

  private static void awaitCurrentConnectionsAtMost(long expected) throws Exception
  {
    final long deadline = System.currentTimeMillis() + TIMEOUT_MS;
    while (DirectoryServer.getCurrentConnections() > expected)
    {
      assertTrue(System.currentTimeMillis() < deadline,
          "the server counts " + DirectoryServer.getCurrentConnections() + " connections, more than " + expected);
      Thread.sleep(10);
    }
  }

  private static void bindAnonymously(Socket client) throws Exception
  {
    final OutputStream out = client.getOutputStream();
    out.write(ANONYMOUS_BIND);
    out.flush();
    client.setSoTimeout((int) TIMEOUT_MS);
    final LDAPMessage response = new LDAPReader(client).readMessage();
    assertNotNull(response, "the connection was closed instead of answering the bind");
    assertEquals(response.getBindResponseProtocolOp().getResultCode(), LDAPResultCode.SUCCESS, "bind result");
  }

  /** Checks that the server neither writes to the connection nor closes it for a while. */
  private static void assertStaysOpen(Socket client) throws Exception
  {
    client.setSoTimeout(STAYS_OPEN_MS);
    try
    {
      final int read = client.getInputStream().read();
      fail("the connection did not stay open: read " + read);
    }
    catch (SocketTimeoutException expected)
    {
      // Neither data nor the end of the stream within the time.
    }
  }

  /**
   * Checks that the server closes the connection in time. Anything the server writes first, such as a TLS alert, is
   * skipped: only the end of the stream matters.
   */
  private static void assertClosedByServer(Socket client) throws Exception
  {
    client.setSoTimeout((int) TIMEOUT_MS);
    final byte[] buffer = new byte[1024];
    try
    {
      while (client.getInputStream().read(buffer) >= 0)
      {
        // Skip what the server writes before closing.
      }
    }
    catch (SocketTimeoutException e)
    {
      throw new AssertionError("the server did not close the connection", e);
    }
  }

  /** Reads the next message from the client, checks it is the expected notice of disconnection, then the end. */
  private static void assertNoticeOfDisconnection(Socket client, LocalizableMessage reason) throws Exception
  {
    client.setSoTimeout((int) TIMEOUT_MS);
    final LDAPMessage message;
    try
    {
      message = new LDAPReader(client).readMessage();
    }
    catch (SocketTimeoutException e)
    {
      throw new AssertionError("the connection is still open", e);
    }
    assertNotNull(message, "the connection was closed without a notice of disconnection");
    final ExtendedResponseProtocolOp notice = message.getExtendedResponseProtocolOp();
    assertEquals(notice.getOID(), NOTICE_OF_DISCONNECTION_OID);
    assertEquals(String.valueOf(notice.getErrorMessage()), reason.toString(), "diagnostic message");
    assertEquals(client.getInputStream().read(), -1, "the connection stayed open after the notice");
  }

  private static void awaitClientConnections(LDAPConnectionHandler handler, int expected) throws Exception
  {
    final long deadline = System.currentTimeMillis() + TIMEOUT_MS;
    while (handler.getClientConnections().size() != expected)
    {
      assertTrue(System.currentTimeMillis() < deadline,
          "the handler holds " + handler.getClientConnections().size() + " connections, not " + expected);
      Thread.sleep(50);
    }
  }

  private static SSLContext trustAll() throws Exception
  {
    final SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, new TrustManager[] { new X509TrustManager()
    {
      @Override
      public void checkClientTrusted(X509Certificate[] chain, String authType)
      {
        // The test trusts the self-signed certificate of the administration connector.
      }

      @Override
      public void checkServerTrusted(X509Certificate[] chain, String authType)
      {
        // The test trusts the self-signed certificate of the administration connector.
      }

      @Override
      public X509Certificate[] getAcceptedIssuers()
      {
        return new X509Certificate[0];
      }
    } }, null);
    return context;
  }

  private static LDAPConnectionHandlerCfg configuration(int port, String... limits) throws Exception
  {
    return configuration(port, false, limits);
  }

  private static LDAPConnectionHandlerCfg sslConfiguration(int port, String... limits) throws Exception
  {
    return configuration(port, true, limits);
  }

  private static LDAPConnectionHandlerCfg configuration(int port, boolean useSSL, String... limits) throws Exception
  {
    final List<String> lines = new ArrayList<>();
    lines.add("dn: cn=Limits Test Handler,cn=Connection Handlers,cn=config");
    lines.add("objectClass: top");
    lines.add("objectClass: ds-cfg-connection-handler");
    lines.add("objectClass: ds-cfg-ldap-connection-handler");
    lines.add("cn: Limits Test Handler");
    lines.add("ds-cfg-java-class: " + LDAPConnectionHandler.class.getName());
    lines.add("ds-cfg-enabled: true");
    lines.add("ds-cfg-listen-address: 127.0.0.1");
    lines.add("ds-cfg-listen-port: " + port);
    lines.add("ds-cfg-keep-stats: false");
    lines.add("ds-cfg-use-ssl: " + useSSL);
    if (useSSL)
    {
      lines.add("ds-cfg-ssl-cert-nickname: server-cert");
      lines.add("ds-cfg-key-manager-provider: cn=JKS,cn=Key Manager Providers,cn=config");
      lines.add("ds-cfg-trust-manager-provider: cn=JKS,cn=Trust Manager Providers,cn=config");
    }
    lines.add("ds-cfg-allow-start-tls: false");
    lines.add("ds-cfg-allow-ldap-v2: false");
    lines.add("ds-cfg-send-rejection-notice: true");
    lines.addAll(Arrays.asList(limits));
    return getConfiguration(TestCaseUtils.makeEntry(lines.toArray(new String[0])));
  }

  private static LDAPConnectionHandler start(LDAPConnectionHandlerCfg config) throws Exception
  {
    final LDAPConnectionHandler handler = new LDAPConnectionHandler();
    handler.initializeConnectionHandler(mock(ServerContext.class), config);
    handler.start();
    return handler;
  }

  private static void stop(LDAPConnectionHandler handler) throws InterruptedException
  {
    if (!handler.isAlive())
    {
      return;
    }
    handler.processServerShutdown(STOP_REASON);
    handler.finalizeConnectionHandler(STOP_REASON);
    handler.join(TIMEOUT_MS);
    assertFalse(handler.isAlive(), "the connection handler thread is still running");
  }
}
