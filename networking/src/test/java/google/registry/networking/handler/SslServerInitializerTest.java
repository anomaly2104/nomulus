// Copyright 2017 The Nomulus Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package google.registry.networking.handler;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.networking.handler.SslInitializerTestUtils.createTrustManager;
import static google.registry.networking.handler.SslInitializerTestUtils.getEcKeyPair;
import static google.registry.networking.handler.SslInitializerTestUtils.getKeyPair;
import static google.registry.networking.handler.SslInitializerTestUtils.setUpSslChannel;
import static google.registry.networking.handler.SslInitializerTestUtils.signIntermediateCa;
import static google.registry.networking.handler.SslInitializerTestUtils.signKeyPair;
import static google.registry.networking.handler.SslInitializerTestUtils.signKeyPairWithEku;
import static google.registry.networking.handler.SslInitializerTestUtils.verifySslException;
import static google.registry.networking.handler.SslServerInitializer.CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY;
import static google.registry.networking.handler.SslServerInitializer.CLIENT_CERTIFICATE_HOSTNAMES_KEY;
import static google.registry.networking.handler.SslServerInitializer.CLIENT_CERTIFICATE_PROMISE_KEY;
import static google.registry.networking.handler.SslServerInitializer.formatHostnamesForLog;
import static google.registry.util.DateTimeUtils.minusDays;
import static google.registry.util.DateTimeUtils.plusDays;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableList;
import google.registry.testing.FakeClock;
import google.registry.util.SelfSignedCaCertificate;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.local.LocalAddress;
import io.netty.channel.local.LocalChannel;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;
import java.nio.channels.ClosedChannelException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Unit tests for {@link SslServerInitializer}.
 *
 * <p>To validate that the handler accepts & rejects connections as expected, a test server and a
 * test client are spun up, and both connect to the {@link LocalAddress} within the JVM. This avoids
 * the overhead of routing traffic through the network layer, even if it were to go through
 * loopback. It also alleviates the need to pick a free port to use.
 *
 * <p>The local addresses used in each test method must be different, otherwise tests run in
 * parallel may interfere with each other.
 */
class SslServerInitializerTest {

  /** Fake host to test if the SSL engine gets the correct peer host. */
  private static final String SSL_HOST = "www.example.tld";

  /** Fake port to test if the SSL engine gets the correct peer port. */
  private static final int SSL_PORT = 12345;

  @RegisterExtension NettyExtension nettyExtension = new NettyExtension();

  @SuppressWarnings("unused")
  static Stream<Arguments> provideTestCombinations() {
    Stream.Builder<Arguments> args = Stream.builder();
    // We do our best effort to test all available SSL providers.
    args.add(Arguments.of(SslProvider.JDK));
    if (OpenSsl.isAvailable()) {
      args.add(Arguments.of(SslProvider.OPENSSL));
    }
    return args.build();
  }

  private ChannelHandler getServerHandler(
      boolean requireClientCert,
      boolean validateClientCert,
      SslProvider sslProvider,
      PrivateKey privateKey,
      X509Certificate... certificates) {
    return new SslServerInitializer<LocalChannel>(
        requireClientCert,
        validateClientCert,
        sslProvider,
        Suppliers.ofInstance(privateKey),
        Suppliers.ofInstance(ImmutableList.copyOf(certificates)));
  }

  private ChannelHandler getClientHandler(
      SslProvider sslProvider,
      X509Certificate trustedCertificate,
      PrivateKey privateKey,
      X509Certificate[] certificates,
      String protocol,
      List<String> cipher) {
    return new ChannelInitializer<LocalChannel>() {
      @Override
      protected void initChannel(LocalChannel ch) throws Exception {
        SslContextBuilder sslContextBuilder =
            SslContextBuilder.forClient()
                .trustManager(trustedCertificate)
                .sslProvider(sslProvider)
                .ciphers(cipher);
        if (protocol != null) {
          sslContextBuilder.protocols(protocol);
        }
        if (privateKey != null && certificates != null && certificates.length > 0) {
          sslContextBuilder.keyManager(privateKey, certificates);
        }
        SslHandler sslHandler =
            sslContextBuilder.build().newHandler(ch.alloc(), SSL_HOST, SSL_PORT);

        // Enable hostname verification.
        SSLEngine sslEngine = sslHandler.engine();
        SSLParameters sslParameters = sslEngine.getSSLParameters();
        sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
        sslEngine.setSSLParameters(sslParameters);

        ch.pipeline().addLast(sslHandler);
      }
    };
  }

  private ChannelHandler getClientHandler(
      SslProvider sslProvider,
      X509Certificate trustedCertificate,
      PrivateKey privateKey,
      X509Certificate certificate,
      String protocol,
      List<String> cipher) {
    return getClientHandler(
        sslProvider,
        trustedCertificate,
        privateKey,
        certificate == null ? null : new X509Certificate[] {certificate},
        protocol,
        cipher);
  }

  private ChannelHandler getClientHandler(
      SslProvider sslProvider,
      X509Certificate trustedCertificate,
      PrivateKey privateKey,
      X509Certificate certificate) {
    return getClientHandler(sslProvider, trustedCertificate, privateKey, certificate, null, null);
  }

  private ChannelHandler getClientHandlerWithChain(
      SslProvider sslProvider,
      X509Certificate trustedCertificate,
      PrivateKey privateKey,
      X509Certificate... certificates) {
    return getClientHandler(sslProvider, trustedCertificate, privateKey, certificates, null, null);
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_swappedInitializerWithSslHandler(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate ssc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SslServerInitializer<EmbeddedChannel> sslServerInitializer =
        new SslServerInitializer<>(
            true,
            false,
            sslProvider,
            Suppliers.ofInstance(ssc.key()),
            Suppliers.ofInstance(ImmutableList.of(ssc.cert())));
    EmbeddedChannel channel = new EmbeddedChannel();
    ChannelPipeline pipeline = channel.pipeline();
    pipeline.addLast(sslServerInitializer);
    ChannelHandler firstHandler = pipeline.first();
    assertThat(firstHandler.getClass()).isEqualTo(SslHandler.class);
    SslHandler sslHandler = (SslHandler) firstHandler;
    assertThat(sslHandler.engine().getNeedClientAuth()).isTrue();
    assertThat(channel.isActive()).isTrue();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_trustAnyClientCert(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    LocalAddress localAddress = new LocalAddress("TRUST_ANY_CLIENT_CERT_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        getServerHandler(true, false, sslProvider, serverSsc.key(), serverSsc.cert()));
    SelfSignedCaCertificate clientSsc = SelfSignedCaCertificate.create(new FakeClock());
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientSsc.key(), clientSsc.cert()));

    SSLSession sslSession = setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    // Verify that the SSL session gets the client cert. Note that this SslSession is for the client
    // channel, therefore its local certificates are the remote certificates of the SslSession for
    // the server channel, and vice versa.
    assertThat(sslSession.getLocalCertificates()).asList().containsExactly(clientSsc.cert());
    assertThat(sslSession.getPeerCertificates()).asList().containsExactly(serverSsc.cert());
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testFailure_cipherNotAccepted(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    LocalAddress localAddress = new LocalAddress("CIPHER_NOT_ACCEPTED_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress, getServerHandler(true, true, sslProvider, serverSsc.key(), serverSsc.cert()));
    SelfSignedCaCertificate clientSsc =
        SelfSignedCaCertificate.create(
            "CLIENT", minusDays(Instant.now(), 2), plusDays(Instant.now(), 1));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider,
            serverSsc.cert(),
            clientSsc.key(),
            clientSsc.cert(),
            "TLSv1.2",
            Collections.singletonList("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")));

    verifySslException(
        nettyExtension.getServerChannel(),
        channel -> channel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get(),
        SSLHandshakeException.class);
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_someCiphersNotAccepted(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    LocalAddress localAddress = new LocalAddress("SOME_CIPHERS_NOT_ACCEPTED_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert()))));
    SelfSignedCaCertificate clientSsc =
        SelfSignedCaCertificate.create(
            "CLIENT", minusDays(Instant.now(), 2), plusDays(Instant.now(), 1));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider,
            serverSsc.cert(),
            clientSsc.key(),
            clientSsc.cert(),
            "TLSv1.2",
            ImmutableList.of(
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", // Only accepted cipher
                "TLS_RSA_WITH_AES_256_CBC_SHA")));

    SSLSession sslSession = setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    assertThat(sslSession.getLocalCertificates()).asList().containsExactly(clientSsc.cert());
    assertThat(sslSession.getPeerCertificates()).asList().containsExactly(serverSsc.cert());
    assertThat(sslSession.getCipherSuite()).isEqualTo("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testFailure_protocolNotAccepted(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    LocalAddress localAddress = new LocalAddress("PROTOCOL_NOT_ACCEPTED_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress, getServerHandler(true, true, sslProvider, serverSsc.key(), serverSsc.cert()));
    SelfSignedCaCertificate clientSsc =
        SelfSignedCaCertificate.create(
            "CLIENT", minusDays(Instant.now(), 2), plusDays(Instant.now(), 1));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientSsc.key(), clientSsc.cert(), "TLSv1.1", null));

    // In JDK v11.0.11 and above, TLS 1.1 is not supported anymore, in which case attempting to
    // connect with TLS 1.1 results in a ClosedChannelException instead of a SSLHandShakeException.
    // See https://www.oracle.com/java/technologies/javase/11-0-11-relnotes.html#JDK-8202343
    Class<? extends Exception> rootCause =
        sslProvider == SslProvider.JDK
            ? ClosedChannelException.class
            : SSLHandshakeException.class;

    verifySslException(
        nettyExtension.getServerChannel(),
        channel -> channel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get(),
        rootCause);
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testFailure_clientCertExpired(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    LocalAddress localAddress = new LocalAddress("CLIENT_CERT_EXPIRED_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress, getServerHandler(true, true, sslProvider, serverSsc.key(), serverSsc.cert()));
    SelfSignedCaCertificate clientSsc =
        SelfSignedCaCertificate.create(
            "CLIENT", minusDays(Instant.now(), 2), minusDays(Instant.now(), 1));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientSsc.key(), clientSsc.cert()));

    verifySslException(
        nettyExtension.getServerChannel(),
        channel -> channel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get(),
        CertificateExpiredException.class);
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testFailure_clientCertNotYetValid(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    LocalAddress localAddress = new LocalAddress("CLIENT_CERT_EXPIRED_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress, getServerHandler(true, true, sslProvider, serverSsc.key(), serverSsc.cert()));
    SelfSignedCaCertificate clientSsc =
        SelfSignedCaCertificate.create(
            "CLIENT", plusDays(Instant.now(), 1), plusDays(Instant.now(), 2));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientSsc.key(), clientSsc.cert()));

    verifySslException(
        nettyExtension.getServerChannel(),
        channel -> channel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get(),
        CertificateNotYetValidException.class);
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_doesNotRequireClientCert(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    LocalAddress localAddress = new LocalAddress("DOES_NOT_REQUIRE_CLIENT_CERT_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        getServerHandler(false, false, sslProvider, serverSsc.key(), serverSsc.cert()));
    nettyExtension.setUpClient(
        localAddress, getClientHandler(sslProvider, serverSsc.cert(), null, null));

    SSLSession sslSession = setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    // Verify that the SSL session does not contain any client cert. Note that this SslSession is
    // for the client channel, therefore its local certificates are the remote certificates of the
    // SslSession for the server channel, and vice versa.
    assertThat(sslSession.getLocalCertificates()).isNull();
    assertThat(sslSession.getPeerCertificates()).asList().containsExactly(serverSsc.cert());
    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isNull();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isNull();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_CertSignedByOtherCa(SslProvider sslProvider) throws Exception {
    // The self-signed cert of the CA.
    SelfSignedCaCertificate caSsc = SelfSignedCaCertificate.create(new FakeClock());
    KeyPair keyPair = getKeyPair();
    X509Certificate serverCert = signKeyPair(caSsc, keyPair, SSL_HOST);
    LocalAddress localAddress = new LocalAddress("CERT_SIGNED_BY_OTHER_CA_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        getServerHandler(
            true,
            false,
            sslProvider,
            keyPair.getPrivate(),
            // Serving both the server cert, and the CA cert
            serverCert,
            caSsc.cert()));
    SelfSignedCaCertificate clientSsc = SelfSignedCaCertificate.create(new FakeClock());
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider,
            // Client trusts the CA cert
            caSsc.cert(),
            clientSsc.key(),
            clientSsc.cert()));

    SSLSession sslSession =
        setUpSslChannel(nettyExtension.getClientChannel(), serverCert, caSsc.cert());
    nettyExtension.assertThatMessagesWork();

    assertThat(sslSession.getLocalCertificates()).asList().containsExactly(clientSsc.cert());
    assertThat(sslSession.getPeerCertificates())
        .asList()
        .containsExactly(serverCert, caSsc.cert())
        .inOrder();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testFailure_requireClientCertificate(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    LocalAddress localAddress = new LocalAddress("REQUIRE_CLIENT_CERT_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        getServerHandler(true, false, sslProvider, serverSsc.key(), serverSsc.cert()));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider,
            serverSsc.cert(),
            // No client cert/private key used.
            null,
            null));

    // When the server rejects the client during handshake due to lack of client certificate, both
    // should throw exceptions.
    nettyExtension.assertThatServerRootCause().isInstanceOf(SSLHandshakeException.class);
    nettyExtension.assertThatClientRootCause().isInstanceOf(SSLException.class);
    assertThat(nettyExtension.getClientChannel().isActive()).isFalse();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testFailure_wrongHostnameInCertificate(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc =
        SelfSignedCaCertificate.create("wrong.com", new FakeClock());
    LocalAddress localAddress = new LocalAddress("WRONG_HOSTNAME_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        getServerHandler(true, false, sslProvider, serverSsc.key(), serverSsc.cert()));
    SelfSignedCaCertificate clientSsc = SelfSignedCaCertificate.create(new FakeClock());
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientSsc.key(), clientSsc.cert()));

    // When the client rejects the server cert due to the wrong hostname, both the server and the
    // client throw exceptions.
    nettyExtension.assertThatClientRootCause().isInstanceOf(CertificateException.class);
    nettyExtension.assertThatClientRootCause().hasMessageThat().contains(SSL_HOST);
    nettyExtension.assertThatServerRootCause().isInstanceOf(SSLException.class);
    assertThat(nettyExtension.getClientChannel().isActive()).isFalse();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_clientCertSignedByTrustedCaWithDnsSans(SslProvider sslProvider)
      throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate clientCaSsc =
        SelfSignedCaCertificate.create(
            "client-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate clientCert =
        signKeyPair(
            clientCaSsc,
            clientKeyPair,
            "Ignored.CommonName.TLD",
            "EPP1.Example.TLD.",
            "epp1.example.tld",
            "*.Sub.Example.TLD",
            "epp2.example.tld");
    LocalAddress localAddress = new LocalAddress("TRUSTED_CA_WITH_SANS_" + sslProvider);

    AtomicReference<Boolean> validatedInListener = new AtomicReference<>();
    AtomicReference<ImmutableList<String>> hostnamesInListener = new AtomicReference<>();
    CountDownLatch listenerFired = new CountDownLatch(1);
    ChannelHandler promiseObserver =
        new ChannelInboundHandlerAdapter() {
          @Override
          public void channelActive(ChannelHandlerContext ctx) throws Exception {
            ctx.channel()
                .attr(CLIENT_CERTIFICATE_PROMISE_KEY)
                .get()
                .addListener(
                    future -> {
                      validatedInListener.set(
                          ctx.channel().attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get());
                      hostnamesInListener.set(
                          ctx.channel().attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get());
                      listenerFired.countDown();
                    });
            super.channelActive(ctx);
          }
        };

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(clientCaSsc.cert()))),
        promiseObserver);
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), clientCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(clientCert);
    assertThat(listenerFired.await(10, TimeUnit.SECONDS)).isTrue();
    assertThat(validatedInListener.get()).isTrue();
    assertThat(hostnamesInListener.get())
        .containsExactly("epp1.example.tld", "*.sub.example.tld", "epp2.example.tld")
        .inOrder();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isTrue();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get())
        .containsExactly("epp1.example.tld", "*.sub.example.tld", "epp2.example.tld")
        .inOrder();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_clientCertSignedByTrustedCaWithCnFallback(SslProvider sslProvider)
      throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate clientCaSsc =
        SelfSignedCaCertificate.create(
            "client-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate clientCert = signKeyPair(clientCaSsc, clientKeyPair, "EPP.CnFallback.TLD.");
    LocalAddress localAddress = new LocalAddress("TRUSTED_CA_CN_FALLBACK_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(clientCaSsc.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), clientCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(clientCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isTrue();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get())
        .containsExactly("epp.cnfallback.tld");
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_clientCertThreeTierChainWithIntermediateCa(SslProvider sslProvider)
      throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    Instant from = Instant.EPOCH;
    Instant to = Instant.parse("2100-01-01T00:00:00Z");
    SelfSignedCaCertificate rootCa = SelfSignedCaCertificate.create("root-ca.tld", from, to);
    KeyPair intermediateKeyPair = getKeyPair();
    X509Certificate intermediateCa =
        signIntermediateCa(rootCa, intermediateKeyPair, "intermediate-ca.tld", from, to);
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate clientCert =
        signKeyPair(
            intermediateKeyPair.getPrivate(),
            intermediateCa,
            clientKeyPair,
            "Ignored.CN.TLD",
            from,
            to,
            "epp.three-tier.example");
    LocalAddress localAddress = new LocalAddress("THREE_TIER_CHAIN_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            false,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(rootCa.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandlerWithChain(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), clientCert, intermediateCa));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(clientCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isTrue();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get())
        .containsExactly("epp.three-tier.example");
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_untrustedClientCert_stillSucceedsHandshakeWithEmptyHostnames(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate untrustedCa =
        SelfSignedCaCertificate.create(
            "untrusted-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    // Use a non-CA leaf signed by an untrusted CA so validateCertificateChain() exercises
    // getDefaultTrustManager() / PKIX rather than short-circuiting on BasicConstraints.
    X509Certificate untrustedLeafCert =
        signKeyPair(untrustedCa, clientKeyPair, "EPP.Untrusted.TLD", "epp.untrusted.tld");
    LocalAddress localAddress = new LocalAddress("UNTRUSTED_CLIENT_EMPTY_HOSTNAMES_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress, getServerHandler(true, true, sslProvider, serverSsc.key(), serverSsc.cert()));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), untrustedLeafCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(untrustedLeafCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isFalse();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_selfSignedCaClientCert_stillSucceedsHandshakeWithEmptyHostnames(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate clientSsc =
        SelfSignedCaCertificate.create(
            "EPP.SelfSigned.TLD", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    LocalAddress localAddress = new LocalAddress("SELF_SIGNED_CA_EMPTY_HOSTNAMES_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress, getServerHandler(true, true, sslProvider, serverSsc.key(), serverSsc.cert()));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientSsc.key(), clientSsc.cert()));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(clientSsc.cert());
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isFalse();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_trustedCaCodeSigningClientCert_chainValidatedFalseAndEmptyHostnames(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate clientCaSsc =
        SelfSignedCaCertificate.create(
            "client-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate codeSigningCert =
        signKeyPairWithEku(
            clientCaSsc,
            clientKeyPair,
            "epp.codesign.example",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning),
            "epp.codesign.example");
    LocalAddress localAddress = new LocalAddress("TRUSTED_CA_CODE_SIGNING_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(clientCaSsc.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), codeSigningCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(codeSigningCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isFalse();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_expiredClientCertWhenValidationDisabled_chainValidatedFalse(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate rootCa =
        SelfSignedCaCertificate.create(
            "root-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate expiredClientCert =
        signKeyPair(
            rootCa,
            clientKeyPair,
            "epp.expired.example",
            Instant.parse("2000-01-01T00:00:00Z"),
            Instant.parse("2000-01-02T00:00:00Z"),
            "epp.expired.example");
    LocalAddress localAddress = new LocalAddress("EXPIRED_CLIENT_NO_VALIDATE_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            false,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(rootCa.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), expiredClientCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(expiredClientCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isFalse();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_notYetValidClientCertWhenValidationDisabled_chainValidatedFalse(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate rootCa =
        SelfSignedCaCertificate.create(
            "root-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate futureClientCert =
        signKeyPair(
            rootCa,
            clientKeyPair,
            "epp.future.example",
            Instant.parse("2099-01-01T00:00:00Z"),
            Instant.parse("2099-01-02T00:00:00Z"),
            "epp.future.example");
    LocalAddress localAddress = new LocalAddress("FUTURE_CLIENT_NO_VALIDATE_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            false,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(rootCa.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), futureClientCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(futureClientCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isFalse();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_ecdsaClientCertSignedByTrustedCa(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate ecRootCa =
        SelfSignedCaCertificate.create(
            getEcKeyPair(), "ec-root-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair ecClientKeyPair = getEcKeyPair();
    X509Certificate ecClientCert =
        signKeyPair(ecRootCa, ecClientKeyPair, "ignored.cn.example", "epp.ecdsa.example");
    LocalAddress localAddress = new LocalAddress("ECDSA_TRUSTED_CA_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            false,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(ecRootCa.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), ecClientKeyPair.getPrivate(), ecClientCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(ecClientCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isTrue();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get())
        .containsExactly("epp.ecdsa.example");
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_trustedCaCertWithoutValidHostnames_emptyHostnamesList(SslProvider sslProvider)
      throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate rootCa =
        SelfSignedCaCertificate.create(
            "root-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate clientCert = signKeyPair(rootCa, clientKeyPair, "Acme Corp");
    LocalAddress localAddress = new LocalAddress("TRUSTED_CA_NO_HOSTNAMES_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            false,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(rootCa.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), clientCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(clientCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isTrue();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testFailure_expiredTrustedClientCertWhenValidationEnabled_doesNotSetChainAttributes(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate rootCa =
        SelfSignedCaCertificate.create(
            "root-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate expiredClientCert =
        signKeyPair(
            rootCa,
            clientKeyPair,
            "epp.expired.example",
            Instant.parse("2000-01-01T00:00:00Z"),
            Instant.parse("2000-01-02T00:00:00Z"),
            "epp.expired.example");
    LocalAddress localAddress = new LocalAddress("EXPIRED_TRUSTED_VALIDATE_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(rootCa.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), expiredClientCert));

    Channel serverChannel = nettyExtension.getServerChannel();
    verifySslException(
        serverChannel,
        channel -> channel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get(),
        CertificateExpiredException.class);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isNull();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isNull();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testFailure_notYetValidTrustedClientCertWhenValidationEnabled_doesNotSetChainAttributes(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate rootCa =
        SelfSignedCaCertificate.create(
            "root-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate futureClientCert =
        signKeyPair(
            rootCa,
            clientKeyPair,
            "epp.future.example",
            Instant.parse("2099-01-01T00:00:00Z"),
            Instant.parse("2099-01-02T00:00:00Z"),
            "epp.future.example");
    LocalAddress localAddress = new LocalAddress("FUTURE_TRUSTED_VALIDATE_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(rootCa.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), futureClientCert));

    Channel serverChannel = nettyExtension.getServerChannel();
    verifySslException(
        serverChannel,
        channel -> channel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get(),
        CertificateNotYetValidException.class);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isNull();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isNull();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_clientCertServerAuthOnlyEku(SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate clientCaSsc =
        SelfSignedCaCertificate.create(
            "client-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate serverAuthOnlyCert =
        signKeyPairWithEku(
            clientCaSsc,
            clientKeyPair,
            "ignored.cn.example",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
            "epp.serverauth.example");
    LocalAddress localAddress = new LocalAddress("SERVER_AUTH_ONLY_EKU_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(clientCaSsc.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), serverAuthOnlyCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(serverAuthOnlyCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isTrue();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get())
        .containsExactly("epp.serverauth.example");
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_trustedCaClientAuthOnlyClientCert_chainValidatedFalseAndEmptyHostnames(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate clientCaSsc =
        SelfSignedCaCertificate.create(
            "client-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate clientAuthOnlyCert =
        signKeyPairWithEku(
            clientCaSsc,
            clientKeyPair,
            "ignored.cn.example",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth),
            "epp.clientauth.example");
    LocalAddress localAddress = new LocalAddress("CLIENT_AUTH_ONLY_EKU_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(clientCaSsc.cert()))));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(
            sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), clientAuthOnlyCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(clientAuthOnlyCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isFalse();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_missingIntermediateCa_chainValidatedFalseAndEmptyHostnames(
      SslProvider sslProvider) throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    Instant from = Instant.EPOCH;
    Instant to = Instant.parse("2100-01-01T00:00:00Z");
    SelfSignedCaCertificate rootCa = SelfSignedCaCertificate.create("root-ca.tld", from, to);
    KeyPair intermediateKeyPair = getKeyPair();
    X509Certificate intermediateCa =
        signIntermediateCa(rootCa, intermediateKeyPair, "intermediate-ca.tld", from, to);
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate clientCert =
        signKeyPair(
            intermediateKeyPair.getPrivate(),
            intermediateCa,
            clientKeyPair,
            "epp.missing-inter.example",
            from,
            to,
            "epp.missing-inter.example");
    LocalAddress localAddress = new LocalAddress("MISSING_INTERMEDIATE_CA_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.of(createTrustManager(rootCa.cert()))));
    // Client sends leaf only, omitting the required intermediate CA.
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), clientCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(clientCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isFalse();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("provideTestCombinations")
  void testSuccess_emptyTrustManager_chainValidatedFalseAndEmptyHostnames(SslProvider sslProvider)
      throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    SelfSignedCaCertificate clientCaSsc =
        SelfSignedCaCertificate.create(
            "client-ca.tld", Instant.EPOCH, Instant.parse("2100-01-01T00:00:00Z"));
    KeyPair clientKeyPair = getKeyPair();
    X509Certificate clientCert =
        signKeyPair(clientCaSsc, clientKeyPair, "epp.notm.example", "epp.notm.example");
    LocalAddress localAddress = new LocalAddress("EMPTY_TRUST_MANAGER_" + sslProvider);

    nettyExtension.setUpServer(
        localAddress,
        new SslServerInitializer<LocalChannel>(
            true,
            true,
            sslProvider,
            Suppliers.ofInstance(serverSsc.key()),
            Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
            Optional.empty()));
    nettyExtension.setUpClient(
        localAddress,
        getClientHandler(sslProvider, serverSsc.cert(), clientKeyPair.getPrivate(), clientCert));

    setUpSslChannel(nettyExtension.getClientChannel(), serverSsc.cert());
    nettyExtension.assertThatMessagesWork();

    Channel serverChannel = nettyExtension.getServerChannel();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_PROMISE_KEY).get().get())
        .isEqualTo(clientCert);
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_CHAIN_VALIDATED_KEY).get()).isFalse();
    assertThat(serverChannel.attr(CLIENT_CERTIFICATE_HOSTNAMES_KEY).get()).isEmpty();
  }

  @Test
  void testFailure_validateClientCertWithoutRequireClientCert_throws() throws Exception {
    SelfSignedCaCertificate serverSsc = SelfSignedCaCertificate.create(SSL_HOST, new FakeClock());
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new SslServerInitializer<LocalChannel>(
                false,
                true,
                SslProvider.JDK,
                Suppliers.ofInstance(serverSsc.key()),
                Suppliers.ofInstance(ImmutableList.of(serverSsc.cert()))));
    assertThrows(
        NullPointerException.class,
        () ->
            new SslServerInitializer<LocalChannel>(
                true,
                false,
                SslProvider.JDK,
                Suppliers.ofInstance(serverSsc.key()),
                Suppliers.ofInstance(ImmutableList.of(serverSsc.cert())),
                null));
  }

  @Test
  void testFormatHostnamesForLog_boundsOutput() {
    assertThrows(NullPointerException.class, () -> formatHostnamesForLog(null));
    assertThat(formatHostnamesForLog(ImmutableList.of())).isEqualTo("[]");
    assertThat(formatHostnamesForLog(ImmutableList.of("epp.example.tld")))
        .isEqualTo("[epp.example.tld]");
    ImmutableList<String> tenHosts =
        IntStream.range(0, 10)
            .mapToObj(i -> "h" + i + ".example.tld")
            .collect(ImmutableList.toImmutableList());
    assertThat(formatHostnamesForLog(tenHosts)).isEqualTo(tenHosts.toString());

    ImmutableList<String> elevenHosts =
        IntStream.range(0, 11)
            .mapToObj(i -> "h" + i + ".example.tld")
            .collect(ImmutableList.toImmutableList());
    assertThat(formatHostnamesForLog(elevenHosts))
        .isEqualTo(
            "[h0.example.tld, h1.example.tld, h2.example.tld, h3.example.tld, h4.example.tld,"
                + " h5.example.tld, h6.example.tld, h7.example.tld, h8.example.tld,"
                + " h9.example.tld, ... (11 total)]");

    ImmutableList<String> fifteenHosts =
        IntStream.range(0, 15)
            .mapToObj(i -> "h" + i + ".example.tld")
            .collect(ImmutableList.toImmutableList());
    assertThat(formatHostnamesForLog(fifteenHosts))
        .isEqualTo(
            "[h0.example.tld, h1.example.tld, h2.example.tld, h3.example.tld, h4.example.tld,"
                + " h5.example.tld, h6.example.tld, h7.example.tld, h8.example.tld,"
                + " h9.example.tld, ... (15 total)]");
  }

  /** Returns true if v1 is larger or equals to v2. */
  private static boolean compareSemanticVersion(
      ImmutableList<Integer> v1, ImmutableList<Integer> v2) {
    for (int i : ImmutableList.of(0, 1, 2)) {
      if (v1.get(i) > v2.get(i)) {
        return true;
      }
      if (v1.get(i) < v2.get(i)) {
        return false;
      }
    }
    return true;
  }
}
