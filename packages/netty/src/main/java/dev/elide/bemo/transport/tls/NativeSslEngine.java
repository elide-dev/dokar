/*
 * Copyright (c) 2024-2026 Elide Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
package dev.elide.bemo.transport.tls;

import dev.elide.bemo.transport.TransportNative;
import io.netty.handler.ssl.ApplicationProtocolSslEngine;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.ReferenceCounted;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.jspecify.annotations.Nullable;

/**
 * {@link javax.net.ssl.SSLEngine} over a Rustls connection in native code. Wrap and unwrap pass
 * buffer addresses: direct buffers and heap arrays are read and written in place, so no TLS record
 * is copied on the JVM side. During the handshake, heap buffers are staged through a bounded direct
 * buffer because handshake crypto must not run while heap arrays are held in place.
 *
 * <p>Unwrap consumes at most one record and may decrypt a writable source in place; callers that
 * reread consumed bytes must pass read-only buffers. Released by {@link #release()}, which Netty's
 * {@code SslHandler} performs on removal; unreleased engines retain their context.
 */
public final class NativeSslEngine extends ApplicationProtocolSslEngine
    implements ReferenceCounted {
  private static final int MAX_RECORD = 5 + 16384 + 2048;
  private static final int MAX_WRAP = 4 * 16384;
  private static final int MAX_LENGTH = (1 << 24) - 1;
  private static final long INBOUND_DONE = 1L << 53;
  private static final long OUTBOUND_DONE = 1L << 54;
  private static final long HANDSHAKING = 1L << 55;
  private static final long TRUNCATED = 1L << 56;
  private static final int FINISHED = 1;
  private static final Status[] STATUS = Status.values();
  private static final HandshakeStatus[] HANDSHAKE = HandshakeStatus.values();

  final NativeSslContext context;
  private final TransportNative api;
  private final NativeSslSession session;
  private final AbstractReferenceCounted references =
      new AbstractReferenceCounted() {
        @Override
        protected void deallocate() {
          free();
        }

        @Override
        public ReferenceCounted touch(Object hint) {
          return this;
        }
      };
  private long handle;
  private long state = HANDSHAKING;
  private boolean established;
  private boolean failed;
  private boolean freed;
  private boolean inboundClosed;
  private boolean outboundClosed;
  private @Nullable String endpointIdentification;
  private @Nullable List<SNIServerName> serverNames;
  private @Nullable ByteBuffer stagingInput;
  private @Nullable ByteBuffer stagingOutput;

  NativeSslEngine(NativeSslContext context, @Nullable String peerHost, int peerPort) {
    super(peerHost, peerPort);
    this.context = context;
    this.api = context.api;
    this.session = new NativeSslSession(this);
    this.endpointIdentification = context.isClient() ? "HTTPS" : null;
    context.retain();
  }

  // ---- Native state ----------------------------------------------------------------------------

  private long handle() throws SSLException {
    if (freed) throw failure("TLS engine was released", false);
    if (handle == 0) {
      byte[] name = null;
      if (context.isClient()) {
        String host = serverName();
        if (host == null) throw failure("TLS client engines require a peer host name", true);
        name = host.getBytes(StandardCharsets.UTF_8);
      }
      handle = context.newEngine(name);
      if (handle == 0) throw failure("Invalid TLS peer name or released context", true);
      if (outboundClosed)
        state = api.engineControl(handle, TransportNative.ENGINE_CONTROL_CLOSE_OUTBOUND);
      if (inboundClosed)
        state = api.engineControl(handle, TransportNative.ENGINE_CONTROL_CLOSE_INBOUND);
    }
    return handle;
  }

  private @Nullable String serverName() {
    if (serverNames != null)
      for (SNIServerName name : serverNames)
        if (name instanceof SNIHostName host) return host.getAsciiName();
    String host = getPeerHost();
    if (host == null || host.isEmpty()) return null;
    return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
  }

  private long check(long packed) throws SSLException {
    if (packed >= 0) {
      state = packed;
      if (!established && (packed & HANDSHAKING) == 0 && !failed) {
        established = true;
        session.established(api, handle);
      }
      return packed;
    }
    boolean handshaking = !established;
    if (packed == TransportNative.ENGINE_FAILED) {
      failed = true;
      String message =
          new String(
              info(api, handle, TransportNative.ENGINE_INFO_FAILURE, 0), StandardCharsets.UTF_8);
      long current = api.engineControl(handle, TransportNative.ENGINE_CONTROL_STATE);
      if (current >= 0) state = current;
      throw failure(message.isEmpty() ? "TLS failure" : message, handshaking);
    }
    throw failure("TLS engine is unavailable", handshaking);
  }

  static byte[] info(TransportNative api, long handle, int kind, int index) {
    byte[] output = new byte[kind == TransportNative.ENGINE_INFO_PEER ? 2048 : 256];
    int length = api.engineInfo(handle, kind, index, output);
    if (length < 0) return new byte[0];
    if (length > output.length) {
      output = new byte[length];
      length = api.engineInfo(handle, kind, index, output);
      if (length < 0) return new byte[0];
    }
    return length == output.length ? output : Arrays.copyOf(output, length);
  }

  boolean failed() {
    return failed;
  }

  private void staging() {
    if (stagingInput == null) {
      ByteBuffer staging = ByteBuffer.allocateDirect(2 * MAX_RECORD);
      stagingInput = staging.slice(0, MAX_RECORD);
      stagingOutput = staging.slice(MAX_RECORD, MAX_RECORD);
    }
  }

  /** Read-only heap buffers expose no array; stage at most one record's worth natively. */
  private ByteBuffer stage(ByteBuffer source, int length) {
    staging();
    ByteBuffer input =
        java.util.Objects.requireNonNull(
            stagingInput, "staging allocates input and output together");
    input.clear();
    input.put(0, source, source.position(), length);
    return input;
  }

  private static SSLEngineResult result(long packed, int consumed, int produced, boolean finished) {
    int handshake = (int) (packed >>> 50 & 7);
    HandshakeStatus status =
        finished && HANDSHAKE[handshake] == HandshakeStatus.NOT_HANDSHAKING
            ? HandshakeStatus.FINISHED
            : HANDSHAKE[handshake];
    return new SSLEngineResult(STATUS[(int) (packed >>> 48 & 3)], status, consumed, produced);
  }

  private static int consumed(long packed) {
    return (int) (packed & MAX_LENGTH);
  }

  private static int produced(long packed) {
    return (int) (packed >>> 24 & MAX_LENGTH);
  }

  private static boolean finished(long packed) {
    return (packed >>> 50 & 7) == FINISHED;
  }

  private static void writable(ByteBuffer destination) {
    if (destination.isReadOnly()) throw new ReadOnlyBufferException();
  }

  // ---- Wrap and unwrap -------------------------------------------------------------------------

  private long wrapOnce(@Nullable ByteBuffer source, ByteBuffer destination) throws SSLException {
    long engine = handle();
    int length = source == null ? 0 : Math.min(source.remaining(), MAX_WRAP);
    ByteBuffer input = source;
    if (source != null && length > 0 && !source.isDirect() && !source.hasArray()) {
      length = Math.min(length, MAX_RECORD);
      input = stage(source, length);
    }
    long packed =
        check(
            api.engineWrap(
                engine, input, length, destination, Math.min(destination.remaining(), MAX_LENGTH)));
    if (source != null) source.position(source.position() + consumed(packed));
    destination.position(destination.position() + produced(packed));
    return packed;
  }

  private long unwrapOnce(ByteBuffer source, int length, ByteBuffer destination)
      throws SSLException {
    long engine = handle();
    boolean handshaking = !established;
    ByteBuffer input = source;
    if (length > 0 && !source.isDirect() && (handshaking || !source.hasArray())) {
      length = Math.min(length, MAX_RECORD);
      input = stage(source, length);
    }
    ByteBuffer output = destination;
    int room = Math.min(destination.remaining(), MAX_LENGTH);
    boolean staged = room > 0 && !destination.isDirect() && handshaking;
    if (staged) {
      staging();
      output =
          java.util.Objects.requireNonNull(
                  stagingOutput, "staging allocates input and output together")
              .clear();
      room = Math.min(room, MAX_RECORD);
    }
    long packed = check(api.engineUnwrap(engine, input, length, output, room));
    int produced = produced(packed);
    if (staged) destination.put(destination.position(), stagingOutput, 0, produced);
    source.position(source.position() + consumed(packed));
    destination.position(destination.position() + produced);
    return packed;
  }

  @Override
  public synchronized SSLEngineResult wrap(ByteBuffer source, ByteBuffer destination)
      throws SSLException {
    writable(destination);
    if (handle == 0 && outboundClosed)
      return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    long packed = wrapOnce(source.hasRemaining() ? source : null, destination);
    return result(packed, consumed(packed), produced(packed), finished(packed));
  }

  @Override
  public synchronized SSLEngineResult wrap(
      ByteBuffer[] sources, int offset, int length, ByteBuffer destination) throws SSLException {
    Objects.checkFromIndexSize(offset, length, sources.length);
    writable(destination);
    if (handle == 0 && outboundClosed)
      return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    int end = offset + length;
    int index = offset;
    while (index < end && !sources[index].hasRemaining()) index++;
    int consumed = 0;
    int produced = 0;
    boolean finished = false;
    long packed;
    for (; ; ) {
      ByteBuffer source = index < end ? sources[index] : null;
      packed = wrapOnce(source, destination);
      consumed += consumed(packed);
      produced += produced(packed);
      finished |= finished(packed);
      if (STATUS[(int) (packed >>> 48 & 3)] != Status.OK || source == null || source.hasRemaining())
        break;
      while (++index < end && !sources[index].hasRemaining()) {}
      if (index == end || !destination.hasRemaining()) break;
    }
    return result(packed, consumed, produced, finished);
  }

  @Override
  public synchronized SSLEngineResult unwrap(ByteBuffer source, ByteBuffer destination)
      throws SSLException {
    writable(destination);
    if (handle == 0 && inboundClosed)
      return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    long packed = unwrapOnce(source, source.remaining(), destination);
    return result(packed, consumed(packed), produced(packed), finished(packed));
  }

  @Override
  public synchronized SSLEngineResult unwrap(
      ByteBuffer source, ByteBuffer[] destinations, int offset, int length) throws SSLException {
    Objects.checkFromIndexSize(offset, length, destinations.length);
    for (int index = offset; index < offset + length; index++) writable(destinations[index]);
    if (handle == 0 && inboundClosed)
      return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    int end = offset + length;
    int index = offset;
    while (index < end - 1 && !destinations[index].hasRemaining()) index++;
    ByteBuffer destination = length == 0 ? ByteBuffer.allocate(0) : destinations[index];
    long packed = unwrapOnce(source, source.remaining(), destination);
    int consumed = consumed(packed);
    int produced = produced(packed);
    boolean finished = finished(packed);
    // Plaintext beyond one destination stays queued natively; drain it into the next ones.
    while (STATUS[(int) (packed >>> 48 & 3)] == Status.BUFFER_OVERFLOW && ++index < end) {
      if (!destinations[index].hasRemaining()) continue;
      packed = unwrapOnce(source, 0, destinations[index]);
      produced += produced(packed);
      finished |= finished(packed);
    }
    return result(packed, consumed, produced, finished);
  }

  // ---- Lifecycle -------------------------------------------------------------------------------

  @Override
  public @Nullable Runnable getDelegatedTask() {
    return null;
  }

  @Override
  public synchronized void beginHandshake() throws SSLException {
    if (established) throw failure("TLS renegotiation is unsupported", false);
    if (inboundClosed || outboundClosed) throw failure("TLS engine is closed", true);
    check(api.engineControl(handle(), TransportNative.ENGINE_CONTROL_BEGIN));
  }

  @Override
  public synchronized HandshakeStatus getHandshakeStatus() {
    if (handle == 0) return HandshakeStatus.NOT_HANDSHAKING;
    HandshakeStatus status = HANDSHAKE[(int) (state >>> 50 & 7)];
    return status == HandshakeStatus.FINISHED ? HandshakeStatus.NOT_HANDSHAKING : status;
  }

  @Override
  public synchronized void closeInbound() throws SSLException {
    if (handle == 0) {
      inboundClosed = true;
      return;
    }
    long packed = api.engineControl(handle, TransportNative.ENGINE_CONTROL_CLOSE_INBOUND);
    if (packed < 0) return;
    state = packed;
    if ((packed & TRUNCATED) != 0)
      throw failure("Inbound closed before receiving the peer's close_notify", false);
  }

  @Override
  public synchronized boolean isInboundDone() {
    return handle == 0 ? inboundClosed : (state & INBOUND_DONE) != 0;
  }

  @Override
  public synchronized void closeOutbound() {
    if (handle == 0) {
      outboundClosed = true;
      return;
    }
    long packed = api.engineControl(handle, TransportNative.ENGINE_CONTROL_CLOSE_OUTBOUND);
    if (packed >= 0) state = packed;
  }

  @Override
  public synchronized boolean isOutboundDone() {
    return handle == 0 ? outboundClosed : (state & OUTBOUND_DONE) != 0;
  }

  private synchronized void free() {
    if (freed) return;
    freed = true;
    if (handle != 0) api.engineRelease(handle);
    handle = 0;
    inboundClosed = outboundClosed = true;
    context.release();
  }

  // ---- Session and parameters ------------------------------------------------------------------

  @Override
  public SSLSession getSession() {
    return session;
  }

  @Override
  public synchronized @Nullable SSLSession getHandshakeSession() {
    return handle != 0 && !established ? session : null;
  }

  @Override
  public @Nullable String getNegotiatedApplicationProtocol() {
    return session.applicationProtocol();
  }

  @Override
  public synchronized @Nullable String getApplicationProtocol() {
    if (!established) return null;
    String protocol = session.applicationProtocol();
    return protocol == null ? "" : protocol;
  }

  @Override
  public @Nullable String getHandshakeApplicationProtocol() {
    return null;
  }

  @Override
  public void setHandshakeApplicationProtocolSelector(
      BiFunction<javax.net.ssl.SSLEngine, List<String>, String> selector) {
    if (selector != null)
      throw new UnsupportedOperationException(
          "ALPN selection is native; configure protocols on NativeSslContextBuilder");
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return NativeSslSession.CIPHER_SUITES.toArray(new String[0]);
  }

  @Override
  public String[] getEnabledCipherSuites() {
    return context.cipherSuites().toArray(new String[0]);
  }

  @Override
  public void setEnabledCipherSuites(String[] suites) {
    requireEnabled(suites, context.cipherSuites(), "cipher suites");
  }

  @Override
  public String[] getSupportedProtocols() {
    return NativeSslSession.PROTOCOLS.toArray(new String[0]);
  }

  @Override
  public String[] getEnabledProtocols() {
    return context.enabledProtocols().toArray(new String[0]);
  }

  @Override
  public void setEnabledProtocols(String[] protocols) {
    requireEnabled(protocols, context.enabledProtocols(), "protocols");
  }

  private static void requireEnabled(String[] requested, List<String> enabled, String kind) {
    Objects.requireNonNull(requested, kind);
    if (!Arrays.asList(requested).equals(enabled))
      throw new IllegalArgumentException(
          "Native TLS engines use the context's "
              + kind
              + "; requested "
              + Arrays.toString(requested));
  }

  @Override
  public void setUseClientMode(boolean mode) {
    if (mode != context.isClient())
      throw new IllegalArgumentException("TLS mode is fixed by the native context");
  }

  @Override
  public boolean getUseClientMode() {
    return context.isClient();
  }

  @Override
  public void setNeedClientAuth(boolean need) {
    if (need) throw new UnsupportedOperationException("Client authentication is not configured");
  }

  @Override
  public boolean getNeedClientAuth() {
    return false;
  }

  @Override
  public void setWantClientAuth(boolean want) {
    if (want) throw new UnsupportedOperationException("Client authentication is not configured");
  }

  @Override
  public boolean getWantClientAuth() {
    return false;
  }

  @Override
  public void setEnableSessionCreation(boolean flag) {
    if (!flag) throw new UnsupportedOperationException("Native TLS engines always create sessions");
  }

  @Override
  public boolean getEnableSessionCreation() {
    return true;
  }

  @Override
  public synchronized SSLParameters getSSLParameters() {
    SSLParameters parameters = new SSLParameters(getEnabledCipherSuites(), getEnabledProtocols());
    parameters.setEndpointIdentificationAlgorithm(endpointIdentification);
    parameters.setApplicationProtocols(context.applicationProtocols().toArray(new String[0]));
    parameters.setUseCipherSuitesOrder(true);
    if (serverNames != null) {
      parameters.setServerNames(serverNames);
    } else if (context.isClient() && serverName() != null && !isIpLiteral(serverName())) {
      List<SNIServerName> materialized = List.of(new SNIHostName(serverName()));
      serverNames = materialized;
      parameters.setServerNames(materialized);
    }
    return parameters;
  }

  /**
   * Rustls always verifies the peer name for clients, so any endpoint identification algorithm is
   * recorded but none disables verification. Server names apply until the engine starts.
   */
  @Override
  public synchronized void setSSLParameters(SSLParameters parameters) {
    if (parameters.getCipherSuites() != null) setEnabledCipherSuites(parameters.getCipherSuites());
    if (parameters.getProtocols() != null) setEnabledProtocols(parameters.getProtocols());
    if (parameters.getNeedClientAuth()) setNeedClientAuth(true);
    else if (parameters.getWantClientAuth()) setWantClientAuth(true);
    String[] protocols = parameters.getApplicationProtocols();
    if (protocols != null
        && protocols.length != 0
        && !Arrays.asList(protocols).equals(context.applicationProtocols()))
      throw new IllegalArgumentException("ALPN protocols are fixed by the native context");
    endpointIdentification = parameters.getEndpointIdentificationAlgorithm();
    List<SNIServerName> names = parameters.getServerNames();
    if (names != null) {
      List<SNIServerName> current = serverNames;
      if (current == null
          && context.isClient()
          && serverName() != null
          && !isIpLiteral(serverName())) current = List.of(new SNIHostName(serverName()));
      if (handle != 0 && !names.equals(current))
        throw new IllegalStateException("TLS server names cannot change after the engine starts");
      serverNames = List.copyOf(names);
    }
  }

  private static boolean isIpLiteral(String host) {
    return host.indexOf(':') >= 0 || host.chars().allMatch(c -> c == '.' || (c >= '0' && c <= '9'));
  }

  // ---- Reference counting ----------------------------------------------------------------------

  @Override
  public int refCnt() {
    return references.refCnt();
  }

  @Override
  public ReferenceCounted retain() {
    references.retain();
    return this;
  }

  @Override
  public ReferenceCounted retain(int increment) {
    references.retain(increment);
    return this;
  }

  @Override
  public ReferenceCounted touch() {
    return this;
  }

  @Override
  public ReferenceCounted touch(Object hint) {
    return this;
  }

  @Override
  public boolean release() {
    return references.release();
  }

  @Override
  public boolean release(int decrement) {
    return references.release(decrement);
  }

  // ---- Failures --------------------------------------------------------------------------------

  static SSLException failure(String message, boolean handshake) {
    return handshake ? new HandshakeFailure(message) : new Failure(message);
  }

  static SSLPeerUnverifiedException unverified() {
    return new Unverified();
  }

  private static final class Failure extends SSLException {
    private static final long serialVersionUID = 1L;

    Failure(String message) {
      super(message);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
      return this;
    }
  }

  private static final class HandshakeFailure extends SSLHandshakeException {
    private static final long serialVersionUID = 1L;

    HandshakeFailure(String message) {
      super(message);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
      return this;
    }
  }

  private static final class Unverified extends SSLPeerUnverifiedException {
    private static final long serialVersionUID = 1L;

    Unverified() {
      super("Peer not authenticated");
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
      return this;
    }
  }
}
