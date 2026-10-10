import dev.elide.bemo.transport.*;
import io.netty.bootstrap.*;
import io.netty.channel.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Verifies that {@code channel.close(promise)} completes the promise even when an asynchronous TLS
 * error pre-empts the 5-second close-timeout fallback. Without the fix, {@code closePromise} is
 * stranded because {@code NativeTlsSession.close()} cancels {@code closeTimeout} without failing
 * the promise.
 */
public final class NativeTlsClosePromiseTest {

  public static void main(String[] args) throws Exception {
    TransportNative delegate = new BackendTransport(new FfmTransportNative(Path.of(args[0])));
    verify(delegate, Files.readAllBytes(Path.of(args[1])), Files.readAllBytes(Path.of(args[2])));
  }

  public static void verify(TransportNative delegate, byte[] cert, byte[] key) throws Exception {
    AtomicBoolean closeInitiated = new AtomicBoolean();
    TransportNative api =
        new BackendTransport(delegate) {
          @Override
          public boolean supportsReceiveResults() {
            return false;
          }

          @Override
          public int tlsStep(
              long session, int action, long plaintext, long offset, long length, long output) {
            if (action == 3) closeInitiated.set(true);
            return super.tlsStep(session, action, plaintext, offset, length, output);
          }

          @Override
          public long socketSend(
              long workload, long driver, long socket, long buffer, long offset, long length) {
            if (closeInitiated.get()) return Long.MAX_VALUE;
            return super.socketSend(workload, driver, socket, buffer, offset, length);
          }
        };
    EventLoopGroup group =
        new MultiThreadIoEventLoopGroup(
            1, NativeIoHandler.newFactory(api, 0, 128, 8 * 1024 * 1024));
    Channel server = null;
    NativeSocketChannel client = null;
    CompletableFuture<NativeSocketChannel> accepted = new CompletableFuture<>();
    try (NativeTlsContext serverTls = NativeTlsContext.server(api, cert, key, "h2");
        NativeTlsContext clientTls = NativeTlsContext.client(api, cert, "h2")) {
      server =
          new ServerBootstrap()
              .group(group)
              .channel(NativeServerSocketChannel.class)
              .childHandler(
                  new ChannelInitializer<NativeSocketChannel>() {
                    @Override
                    protected void initChannel(NativeSocketChannel channel) {
                      channel.tls(serverTls, null);
                      accepted.complete(channel);
                    }
                  })
              .bind(new InetSocketAddress("127.0.0.1", 0))
              .sync()
              .channel();
      client =
          (NativeSocketChannel)
              new Bootstrap()
                  .group(group)
                  .channelFactory(() -> new NativeSocketChannel().tls(clientTls, "localhost"))
                  .handler(
                      new ChannelInboundHandlerAdapter() {
                        @Override
                        public void exceptionCaught(
                            ChannelHandlerContext context, Throwable error) {
                          context.close();
                        }
                      })
                  .connect(server.localAddress())
                  .sync()
                  .channel();
      client.handshakeFuture().sync();
      NativeSocketChannel peer = accepted.get(5, TimeUnit.SECONDS);
      peer.handshakeFuture().sync();
      ChannelPromise closePromise = client.newPromise();
      NativeSocketChannel c = client;
      group
          .next()
          .execute(
              () -> {
                peer.deregister();
                c.unsafe().close(closePromise);
              });
      if (!client.closeFuture().await(5, TimeUnit.SECONDS))
        throw new AssertionError("closeFuture did not complete (channel hung)");
      if (!closePromise.await(2, TimeUnit.SECONDS))
        throw new AssertionError("closePromise stranded after async TLS error");
      if (closePromise.isSuccess())
        throw new AssertionError("closePromise succeeded on error path");
      if (!(closePromise.cause() instanceof java.nio.channels.ClosedChannelException))
        throw new AssertionError(
            "closePromise failed with unexpected cause: " + closePromise.cause());
      System.out.println("Native TLS close-promise completion on async error passed");
    } finally {
      if (client != null) client.close().syncUninterruptibly();
      if (server != null) server.close().syncUninterruptibly();
      group.shutdownGracefully(0, 5, TimeUnit.SECONDS).syncUninterruptibly();
    }
  }
}
