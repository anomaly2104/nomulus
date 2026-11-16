// Copyright 2026 The Nomulus Authors. All Rights Reserved.
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

package google.registry.util;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.util.X509Utils.MAX_CERTIFICATE_CHAIN_LENGTH;
import static google.registry.util.X509Utils.MAX_HOSTNAMES_HEADER_BYTES;
import static google.registry.util.X509Utils.extractHostnames;
import static google.registry.util.X509Utils.formatHostnamesHeader;
import static google.registry.util.X509Utils.getDefaultTrustManager;
import static google.registry.util.X509Utils.validateCertificateChain;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.testing.TestLogHandler;
import google.registry.util.X509Utils.CertificateChainValidationResult;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.IntStream;
import javax.annotation.Nullable;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link X509Utils}. */
class X509UtilsTest {

  private static final Instant VALID_FROM = Instant.EPOCH;
  private static final Instant VALID_TO = Instant.parse("2100-01-01T00:00:00Z");
  private static final Instant EXPIRED_FROM = Instant.parse("2000-01-01T00:00:00Z");
  private static final Instant EXPIRED_TO = Instant.parse("2000-01-02T00:00:00Z");
  private static final Instant FUTURE_FROM = Instant.parse("2099-01-01T00:00:00Z");
  private static final Instant FUTURE_TO = Instant.parse("2099-01-02T00:00:00Z");

  private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
  private static final KeyPairGenerator RSA_KEY_PAIR_GENERATOR = createRsaKeyPairGenerator();
  private static final KeyPairGenerator EC_KEY_PAIR_GENERATOR = createEcKeyPairGenerator();
  private static final AtomicLong SERIAL_NUMBER = new AtomicLong(1);
  private static final DateTimeFormatter UTC_TIME_FORMATTER =
      DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
  private static final DateTimeFormatter GENERALIZED_TIME_FORMATTER =
      DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

  private static SelfSignedCaCertificate rootCa;
  private static SelfSignedCaCertificate untrustedCa;
  private static X509TrustManager rootTrustManager;

  @BeforeAll
  static void setUpSharedCas() throws Exception {
    rootCa = SelfSignedCaCertificate.create("root-ca.tld", VALID_FROM, VALID_TO);
    untrustedCa = SelfSignedCaCertificate.create("untrusted-ca.tld", VALID_FROM, VALID_TO);
    rootTrustManager = createTrustManager(rootCa.cert());
  }

  private static Time toAsn1Time(Instant instant) {
    int year = instant.atOffset(ZoneOffset.UTC).getYear();
    return year >= 2050
        ? new Time(new DERGeneralizedTime(GENERALIZED_TIME_FORMATTER.format(instant)))
        : new Time(new DERUTCTime(UTC_TIME_FORMATTER.format(instant)));
  }

  private static KeyPairGenerator createRsaKeyPairGenerator() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", PROVIDER);
      keyPairGenerator.initialize(2048, new SecureRandom());
      return keyPairGenerator;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static KeyPairGenerator createEcKeyPairGenerator() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", PROVIDER);
      keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
      return keyPairGenerator;
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  private static KeyPair generateKeyPair() {
    return RSA_KEY_PAIR_GENERATOR.generateKeyPair();
  }

  private static KeyPair generateEcKeyPair() {
    return EC_KEY_PAIR_GENERATOR.generateKeyPair();
  }

  private static KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private static String signatureAlgorithmFor(PrivateKey key) {
    return "EC".equals(key.getAlgorithm()) ? "SHA256WithECDSA" : "SHA256WithRSAEncryption";
  }

  private static X509TrustManager createTrustManager(X509Certificate... trustedCerts)
      throws Exception {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    for (int i = 0; i < trustedCerts.length; i++) {
      keyStore.setCertificateEntry("ca-" + i, trustedCerts[i]);
    }
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
    trustManagerFactory.init(keyStore);
    return (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
  }

  private static void assertChainValid(Certificate[] certs, X509TrustManager trustManager) {
    CertificateChainValidationResult result = validateCertificateChain(certs, trustManager);
    assertThat(result.valid()).isTrue();
    assertThat(result.failureReason()).isEmpty();
  }

  private static CertificateChainValidationResult assertChainInvalid(
      @Nullable Certificate[] certs, @Nullable X509TrustManager trustManager) {
    CertificateChainValidationResult result = validateCertificateChain(certs, trustManager);
    assertThat(result.valid()).isFalse();
    assertThat(result.failureReason()).isPresent();
    assertThat(result.failureReason().get()).isNotEmpty();
    return result;
  }

  private static X509Certificate signLeaf(
      PrivateKey issuerKey,
      X509Certificate issuerCert,
      KeyPair keyPair,
      String cn,
      Instant from,
      Instant to,
      String... dnsSans)
      throws Exception {
    X500Name issuerDnName = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());
    ContentSigner sigGen =
        new JcaContentSignerBuilder(signatureAlgorithmFor(issuerKey)).build(issuerKey);
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerDnName,
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(from),
            toAsn1Time(to),
            new X500Name("CN=" + cn),
            keyPair.getPublic());
    if (dnsSans.length > 0) {
      GeneralName[] generalNames =
          Arrays.stream(dnsSans)
              .map(san -> new GeneralName(GeneralName.dNSName, san))
              .toArray(GeneralName[]::new);
      builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames));
    }
    return new JcaX509CertificateConverter()
        .setProvider(PROVIDER)
        .getCertificate(builder.build(sigGen));
  }

  private static X509Certificate signLeaf(
      SelfSignedCaCertificate ssc, KeyPair keyPair, String cn, String... dnsSans) throws Exception {
    return signLeaf(ssc.key(), ssc.cert(), keyPair, cn, VALID_FROM, VALID_TO, dnsSans);
  }

  private static X509Certificate signIntermediateCa(
      PrivateKey issuerKey,
      X509Certificate issuerCert,
      KeyPair keyPair,
      String cn,
      Instant from,
      Instant to,
      BasicConstraints basicConstraints)
      throws Exception {
    X500Name issuerDnName = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());
    ContentSigner sigGen =
        new JcaContentSignerBuilder(signatureAlgorithmFor(issuerKey)).build(issuerKey);
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerDnName,
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(from),
            toAsn1Time(to),
            new X500Name("CN=" + cn),
            keyPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, basicConstraints);
    return new JcaX509CertificateConverter()
        .setProvider(PROVIDER)
        .getCertificate(builder.build(sigGen));
  }

  private static X509Certificate signIntermediateCaWithKeyUsage(
      SelfSignedCaCertificate issuer, KeyPair keyPair, String cn, KeyUsage keyUsage)
      throws Exception {
    X500Name issuerDnName =
        X500Name.getInstance(issuer.cert().getSubjectX500Principal().getEncoded());
    ContentSigner sigGen =
        new JcaContentSignerBuilder(signatureAlgorithmFor(issuer.key())).build(issuer.key());
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerDnName,
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=" + cn),
            keyPair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(Extension.keyUsage, true, keyUsage);
    return new JcaX509CertificateConverter()
        .setProvider(PROVIDER)
        .getCertificate(builder.build(sigGen));
  }

  private static X509Certificate signLeafWithExtensions(
      SelfSignedCaCertificate ssc,
      KeyPair keyPair,
      String cn,
      @Nullable ExtendedKeyUsage extendedKeyUsage,
      @Nullable KeyUsage keyUsage,
      String... dnsSans)
      throws Exception {
    X500Name issuerDnName = X500Name.getInstance(ssc.cert().getSubjectX500Principal().getEncoded());
    ContentSigner sigGen =
        new JcaContentSignerBuilder(signatureAlgorithmFor(ssc.key())).build(ssc.key());
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerDnName,
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=" + cn),
            keyPair.getPublic());
    if (extendedKeyUsage != null) {
      builder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
    }
    if (keyUsage != null) {
      builder.addExtension(Extension.keyUsage, true, keyUsage);
    }
    if (dnsSans.length > 0) {
      GeneralName[] generalNames =
          Arrays.stream(dnsSans)
              .map(san -> new GeneralName(GeneralName.dNSName, san))
              .toArray(GeneralName[]::new);
      builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames));
    }
    return new JcaX509CertificateConverter()
        .setProvider(PROVIDER)
        .getCertificate(builder.build(sigGen));
  }

  private static X509Certificate signLeafWithEku(
      SelfSignedCaCertificate ssc,
      KeyPair keyPair,
      String cn,
      ExtendedKeyUsage extendedKeyUsage,
      String... dnsSans)
      throws Exception {
    return signLeafWithExtensions(ssc, keyPair, cn, extendedKeyUsage, null, dnsSans);
  }

  private static X509Certificate signLeafWithGeneralNames(
      SelfSignedCaCertificate ssc,
      KeyPair keyPair,
      X500Name subjectDnName,
      GeneralName... subjectAltNames)
      throws Exception {
    X500Name issuerDnName = X500Name.getInstance(ssc.cert().getSubjectX500Principal().getEncoded());
    ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(ssc.key());
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerDnName,
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            subjectDnName,
            keyPair.getPublic());
    if (subjectAltNames.length > 0) {
      builder.addExtension(
          Extension.subjectAlternativeName, false, new GeneralNames(subjectAltNames));
    }
    return new JcaX509CertificateConverter()
        .setProvider(PROVIDER)
        .getCertificate(builder.build(sigGen));
  }

  private static X509Certificate signLeafWithGeneralNames(
      SelfSignedCaCertificate ssc,
      KeyPair keyPair,
      String subjectDn,
      GeneralName... subjectAltNames)
      throws Exception {
    return signLeafWithGeneralNames(ssc, keyPair, new X500Name(subjectDn), subjectAltNames);
  }

  private static X509Certificate signLeafWithMalformedSanExtension(
      SelfSignedCaCertificate ssc, KeyPair keyPair, String subjectDn) throws Exception {
    X500Name issuerDnName = X500Name.getInstance(ssc.cert().getSubjectX500Principal().getEncoded());
    ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(ssc.key());
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerDnName,
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name(subjectDn),
            keyPair.getPublic());
    builder.addExtension(Extension.subjectAlternativeName, false, new byte[] {0x01, 0x02, 0x03});
    return new JcaX509CertificateConverter()
        .setProvider(PROVIDER)
        .getCertificate(builder.build(sigGen));
  }

  private static X509Certificate signLeafWithEmptySanSequence(
      SelfSignedCaCertificate ssc, KeyPair keyPair, String subjectDn) throws Exception {
    X500Name issuerDnName = X500Name.getInstance(ssc.cert().getSubjectX500Principal().getEncoded());
    ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(ssc.key());
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerDnName,
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name(subjectDn),
            keyPair.getPublic());
    builder.addExtension(Extension.subjectAlternativeName, false, new DERSequence());
    return new JcaX509CertificateConverter()
        .setProvider(PROVIDER)
        .getCertificate(builder.build(sigGen));
  }

  @Test
  void testCertificateChainValidationResult_validation() {
    assertThat(CertificateChainValidationResult.ok().valid()).isTrue();
    assertThat(CertificateChainValidationResult.ok().failureReason()).isEmpty();
    assertThrows(NullPointerException.class, () -> new CertificateChainValidationResult(null));
    assertThrows(NullPointerException.class, () -> CertificateChainValidationResult.failed(null));
    assertThrows(IllegalArgumentException.class, () -> CertificateChainValidationResult.failed(""));
    assertThrows(
        IllegalArgumentException.class, () -> CertificateChainValidationResult.failed("   "));
  }

  @Test
  void testGetDefaultTrustManager_returnsNonEmptyMemoizedInstance() {
    X509TrustManager trustManager = getDefaultTrustManager();
    assertThat(trustManager).isNotNull();
    assertThat(trustManager.getAcceptedIssuers()).isNotEmpty();
    assertThat(getDefaultTrustManager()).isSameInstanceAs(trustManager);
  }

  @Test
  void testValidateCertificateChain_directAndMultiTierChains_succeed() throws Exception {
    X509Certificate directLeaf = signLeaf(rootCa, generateKeyPair(), "epp.direct.example");
    assertChainValid(new Certificate[] {directLeaf}, rootTrustManager);
    // Chain that includes the trailing root CA certificate itself should validate.
    assertChainValid(new Certificate[] {directLeaf, rootCa.cert()}, rootTrustManager);
    // Trailing null / non-X509 elements are ignored if a valid path exists.
    assertChainValid(new Certificate[] {directLeaf, null}, rootTrustManager);

    // 3-tier chain: root -> intermediate -> leaf.
    KeyPair intermediateKeyPair = generateKeyPair();
    X509Certificate intermediateCa =
        signIntermediateCa(
            rootCa.key(),
            rootCa.cert(),
            intermediateKeyPair,
            "intermediate-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(true));
    X509Certificate threeTierLeaf =
        signLeaf(
            intermediateKeyPair.getPrivate(),
            intermediateCa,
            generateKeyPair(),
            "epp.three-tier.example",
            VALID_FROM,
            VALID_TO);
    assertChainValid(new Certificate[] {threeTierLeaf, intermediateCa}, rootTrustManager);
    assertChainValid(
        new Certificate[] {threeTierLeaf, intermediateCa, rootCa.cert()}, rootTrustManager);
    // Out-of-order chain and extra unrelated cert should still build a valid path.
    assertChainValid(
        new Certificate[] {threeTierLeaf, rootCa.cert(), intermediateCa}, rootTrustManager);
    assertChainValid(
        new Certificate[] {threeTierLeaf, intermediateCa, untrustedCa.cert()}, rootTrustManager);

    // Multi-anchor trust store: validates against a non-first trust anchor.
    SelfSignedCaCertificate secondRootCa =
        SelfSignedCaCertificate.create("second-root-ca.tld", VALID_FROM, VALID_TO);
    X509TrustManager multiTrustManager = createTrustManager(rootCa.cert(), secondRootCa.cert());
    X509Certificate secondRootLeaf =
        signLeaf(secondRootCa, generateKeyPair(), "epp.second-root.example");
    assertChainValid(new Certificate[] {secondRootLeaf}, multiTrustManager);

    // 4-tier chain respecting pathLenConstraint=1: root -> inter1(pathLen=1) -> subCa -> leaf.
    KeyPair pathLen1KeyPair = generateKeyPair();
    X509Certificate pathLen1Inter =
        signIntermediateCa(
            rootCa.key(),
            rootCa.cert(),
            pathLen1KeyPair,
            "pathlen1-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(1));
    KeyPair validSubCaKeyPair = generateKeyPair();
    X509Certificate validSubCa =
        signIntermediateCa(
            pathLen1KeyPair.getPrivate(),
            pathLen1Inter,
            validSubCaKeyPair,
            "valid-sub-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(0));
    X509Certificate fourTierLeaf =
        signLeaf(
            validSubCaKeyPair.getPrivate(),
            validSubCa,
            generateKeyPair(),
            "epp.four-tier.example",
            VALID_FROM,
            VALID_TO);
    assertChainValid(new Certificate[] {fourTierLeaf, validSubCa, pathLen1Inter}, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_exactMaxChainLength_succeeds() throws Exception {
    X509Certificate directLeaf = signLeaf(rootCa, generateKeyPair(), "epp.maxlen.example");
    Certificate[] exactMaxChain = new Certificate[MAX_CERTIFICATE_CHAIN_LENGTH];
    exactMaxChain[0] = directLeaf;
    for (int i = 1; i < MAX_CERTIFICATE_CHAIN_LENGTH; i++) {
      exactMaxChain[i] = rootCa.cert();
    }
    assertChainValid(exactMaxChain, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_ecdsaAndEd25519Chains_succeed() throws Exception {
    // ECDSA 3-tier chain (matching modern EC public CA hierarchies such as Let's Encrypt E5/E6).
    SelfSignedCaCertificate ecRootCa =
        SelfSignedCaCertificate.create(generateEcKeyPair(), "ec-root-ca.tld", VALID_FROM, VALID_TO);
    KeyPair ecInterKeyPair = generateEcKeyPair();
    X509Certificate ecIntermediateCa =
        signIntermediateCa(
            ecRootCa.key(),
            ecRootCa.cert(),
            ecInterKeyPair,
            "ec-intermediate-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(true));
    X509Certificate ecLeaf =
        signLeaf(
            ecInterKeyPair.getPrivate(),
            ecIntermediateCa,
            generateEcKeyPair(),
            "epp.ecdsa.example",
            VALID_FROM,
            VALID_TO,
            "epp.ecdsa.example");
    assertChainValid(
        new Certificate[] {ecLeaf, ecIntermediateCa}, createTrustManager(ecRootCa.cert()));

    // Ed25519 leaf with serverAuth-only EKU and digitalSignature KeyUsage.
    X509Certificate ed25519Leaf =
        signLeafWithExtensions(
            rootCa,
            generateEd25519KeyPair(),
            "epp.ed25519.example",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
            new KeyUsage(KeyUsage.digitalSignature),
            "epp.ed25519.example");
    assertChainValid(new Certificate[] {ed25519Leaf}, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_supportedExtendedKeyUsagesAndCommercialProfile_succeed()
      throws Exception {
    // serverAuth-only, dual-EKU, anyExtendedKeyUsage, and mixed serverAuth+codeSigning leaves.
    X509Certificate serverAuthOnlyLeaf =
        signLeafWithExtensions(
            rootCa,
            generateKeyPair(),
            "epp.serverauth.example",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
            new KeyUsage(KeyUsage.digitalSignature),
            "epp.serverauth.example");
    assertChainValid(new Certificate[] {serverAuthOnlyLeaf}, rootTrustManager);

    X509Certificate dualEkuLeaf =
        signLeafWithEku(
            rootCa,
            generateKeyPair(),
            "epp.dualeku.example",
            new ExtendedKeyUsage(
                new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}),
            "epp.dualeku.example");
    assertChainValid(new Certificate[] {dualEkuLeaf}, rootTrustManager);

    X509Certificate anyEkuLeaf =
        signLeafWithEku(
            rootCa,
            generateKeyPair(),
            "epp.anyeku.example",
            new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage),
            "epp.anyeku.example");
    assertChainValid(new Certificate[] {anyEkuLeaf}, rootTrustManager);

    X509Certificate anyEkuPlusClientLeaf =
        signLeafWithEku(
            rootCa,
            generateKeyPair(),
            "epp.any-plus-client.example",
            new ExtendedKeyUsage(
                new KeyPurposeId[] {
                  KeyPurposeId.anyExtendedKeyUsage, KeyPurposeId.id_kp_clientAuth
                }),
            "epp.any-plus-client.example");
    assertChainValid(new Certificate[] {anyEkuPlusClientLeaf}, rootTrustManager);

    X509Certificate mixedEkuLeaf =
        signLeafWithEku(
            rootCa,
            generateKeyPair(),
            "epp.mixedeku.example",
            new ExtendedKeyUsage(
                new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_codeSigning}),
            "epp.mixedeku.example");
    assertChainValid(new Certificate[] {mixedEkuLeaf}, rootTrustManager);

    // Realistic commercial RSA leaf with critical BasicConstraints(ca=false) and combined
    // KeyUsage(digitalSignature | keyEncipherment).
    X509v3CertificateBuilder commercialLeafBuilder =
        new JcaX509v3CertificateBuilder(
            X500Name.getInstance(rootCa.cert().getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=epp.commercial.example"),
            generateKeyPair().getPublic());
    commercialLeafBuilder.addExtension(
        Extension.basicConstraints, true, new BasicConstraints(false));
    commercialLeafBuilder.addExtension(
        Extension.keyUsage,
        true,
        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
    commercialLeafBuilder.addExtension(
        Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
    commercialLeafBuilder.addExtension(
        Extension.subjectAlternativeName,
        false,
        new GeneralNames(new GeneralName(GeneralName.dNSName, "epp.commercial.example")));
    X509Certificate commercialLeaf =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                commercialLeafBuilder.build(
                    new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootCa.key())));
    assertChainValid(new Certificate[] {commercialLeaf}, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_alwaysUsesCheckServerTrustedOnly() throws Exception {
    // All leaves — regardless of EKU — must go through checkServerTrusted so OpenJDK's TLSServer
    // CADistrustPolicy and SHA-1 constraints are always enforced without fallback.
    ImmutableList<X509Certificate> leaves =
        ImmutableList.of(
            signLeaf(rootCa, generateKeyPair(), "epp.noeku.example"),
            signLeafWithEku(
                rootCa,
                generateKeyPair(),
                "epp.serverauth.example",
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)),
            signLeafWithEku(
                rootCa,
                generateKeyPair(),
                "epp.dualeku.example",
                new ExtendedKeyUsage(
                    new KeyPurposeId[] {
                      KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth
                    })),
            signLeafWithEku(
                rootCa,
                generateKeyPair(),
                "epp.clientauth.example",
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)),
            signLeafWithEku(
                rootCa,
                generateKeyPair(),
                "epp.anyeku.example",
                new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage)));

    for (X509Certificate leaf : leaves) {
      X509TrustManager acceptingTm = mock(X509TrustManager.class);
      doNothing().when(acceptingTm).checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
      assertChainValid(new Certificate[] {leaf}, acceptingTm);
      verify(acceptingTm).checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
      verify(acceptingTm, never()).checkClientTrusted(any(X509Certificate[].class), eq("UNKNOWN"));

      X509TrustManager rejectingTm = mock(X509TrustManager.class);
      doThrow(new CertificateException("distrusted CA"))
          .when(rejectingTm)
          .checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
      CertificateChainValidationResult result =
          assertChainInvalid(new Certificate[] {leaf}, rejectingTm);
      assertThat(result.failureReason()).hasValue("CertificateException: distrusted CA");
      verify(rejectingTm).checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
      verify(rejectingTm, never()).checkClientTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
    }
  }

  @Test
  void testValidateCertificateChain_crossSignedIntermediateBacktracks() throws Exception {
    KeyPair intermediateKeyPair = generateKeyPair();
    X509Certificate validIntermediate =
        signIntermediateCa(
            rootCa.key(),
            rootCa.cert(),
            intermediateKeyPair,
            "intermediate-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(true));
    X509Certificate expiredCrossSignedIntermediate =
        signIntermediateCa(
            untrustedCa.key(),
            untrustedCa.cert(),
            intermediateKeyPair,
            "intermediate-ca.tld",
            EXPIRED_FROM,
            EXPIRED_TO,
            new BasicConstraints(true));
    X509Certificate leaf =
        signLeaf(
            intermediateKeyPair.getPrivate(),
            validIntermediate,
            generateKeyPair(),
            "epp.cross-signed.example",
            VALID_FROM,
            VALID_TO);
    assertChainValid(
        new Certificate[] {leaf, expiredCrossSignedIntermediate, validIntermediate},
        rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_nameConstraintsPermitted_succeeds() throws Exception {
    KeyPair ncInterKeyPair = generateKeyPair();
    X509v3CertificateBuilder ncInterBuilder =
        new JcaX509v3CertificateBuilder(
            X500Name.getInstance(rootCa.cert().getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=nc-intermediate.tld"),
            ncInterKeyPair.getPublic());
    ncInterBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    ncInterBuilder.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    ncInterBuilder.addExtension(
        Extension.nameConstraints,
        true,
        new NameConstraints(
            new GeneralSubtree[] {
              new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".allowed.example"))
            },
            null));
    X509Certificate ncInter =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                ncInterBuilder.build(
                    new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootCa.key())));
    X509Certificate allowedNcLeaf =
        signLeaf(
            ncInterKeyPair.getPrivate(),
            ncInter,
            generateKeyPair(),
            "epp.allowed.example",
            VALID_FROM,
            VALID_TO,
            "epp.allowed.example");
    assertChainValid(new Certificate[] {allowedNcLeaf, ncInter}, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_unreachableOcspAndCrl_succeedsWithoutNetworkIo()
      throws Exception {
    // Leaf carrying unreachable OCSP AIA and CRL Distribution Points must still validate with no
    // network revocation I/O (OpenJDK PKIX disables online revocation by default).
    X509v3CertificateBuilder revInfoLeafBuilder =
        new JcaX509v3CertificateBuilder(
            X500Name.getInstance(rootCa.cert().getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=epp.revinfo.example"),
            generateKeyPair().getPublic());
    revInfoLeafBuilder.addExtension(
        Extension.authorityInfoAccess,
        false,
        new AuthorityInformationAccess(
            new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(
                    GeneralName.uniformResourceIdentifier, "http://127.0.0.1:1/ocsp"))));
    revInfoLeafBuilder.addExtension(
        Extension.cRLDistributionPoints,
        false,
        new CRLDistPoint(
            new DistributionPoint[] {
              new DistributionPoint(
                  new DistributionPointName(
                      new GeneralNames(
                          new GeneralName(
                              GeneralName.uniformResourceIdentifier,
                              "http://127.0.0.1:1/crl.pem"))),
                  null,
                  null)
            }));
    X509Certificate revInfoLeaf =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                revInfoLeafBuilder.build(
                    new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootCa.key())));
    assertChainValid(new Certificate[] {revInfoLeaf}, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_missingOrNonX509Inputs_rejected() throws Exception {
    X509Certificate directLeaf = signLeaf(rootCa, generateKeyPair(), "epp.direct.example");
    assertThat(assertChainInvalid(null, rootTrustManager).failureReason())
        .hasValue("No peer certificates presented");
    assertThat(assertChainInvalid(new Certificate[0], rootTrustManager).failureReason())
        .hasValue("No peer certificates presented");
    assertThat(assertChainInvalid(new Certificate[] {null}, rootTrustManager).failureReason())
        .hasValue("Leaf certificate is not an X509Certificate");
    assertThat(assertChainInvalid(new Certificate[] {directLeaf}, null).failureReason())
        .hasValue("Trust manager is not configured");

    Certificate nonX509Cert =
        new Certificate("CUSTOM") {
          @Override
          public byte[] getEncoded() {
            return new byte[0];
          }

          @Override
          public void verify(PublicKey key) {}

          @Override
          public void verify(PublicKey key, String sigProvider) {}

          @Override
          public String toString() {
            return "non-x509";
          }

          @Override
          public PublicKey getPublicKey() {
            return null;
          }
        };
    assertThat(
            assertChainInvalid(new Certificate[] {nonX509Cert}, rootTrustManager).failureReason())
        .hasValue("Leaf certificate is not an X509Certificate");
  }

  @Test
  void testValidateCertificateChain_exceedsMaxChainLength_rejectedWithoutCallingTrustManager()
      throws Exception {
    X509Certificate directLeaf = signLeaf(rootCa, generateKeyPair(), "epp.toolong.example");
    Certificate[] oversizedChain = new Certificate[MAX_CERTIFICATE_CHAIN_LENGTH + 1];
    oversizedChain[0] = directLeaf;
    for (int i = 1; i < oversizedChain.length; i++) {
      oversizedChain[i] = rootCa.cert();
    }
    X509TrustManager mockTm = mock(X509TrustManager.class);
    CertificateChainValidationResult result = assertChainInvalid(oversizedChain, mockTm);
    assertThat(result.failureReason())
        .hasValue(
            String.format(
                "Certificate chain length %d exceeds maximum of %d",
                MAX_CERTIFICATE_CHAIN_LENGTH + 1, MAX_CERTIFICATE_CHAIN_LENGTH));
    verify(mockTm, never()).checkServerTrusted(any(), any());
    verify(mockTm, never()).checkClientTrusted(any(), any());
  }

  @Test
  void testValidateCertificateChain_caAsLeaf_rejected() throws Exception {
    assertThat(
            assertChainInvalid(new Certificate[] {rootCa.cert()}, rootTrustManager).failureReason())
        .hasValue("Leaf certificate must not be a CA");
    assertThat(
            assertChainInvalid(new Certificate[] {untrustedCa.cert()}, rootTrustManager)
                .failureReason())
        .hasValue("Leaf certificate must not be a CA");

    X509Certificate intermediateCa =
        signIntermediateCa(
            rootCa.key(),
            rootCa.cert(),
            generateKeyPair(),
            "intermediate-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(true));
    assertThat(
            assertChainInvalid(new Certificate[] {intermediateCa}, rootTrustManager)
                .failureReason())
        .hasValue("Leaf certificate must not be a CA");

    SelfSignedCaCertificate expiredRoot =
        SelfSignedCaCertificate.create("expired-root.tld", EXPIRED_FROM, EXPIRED_TO);
    assertThat(
            assertChainInvalid(
                    new Certificate[] {expiredRoot.cert()}, createTrustManager(expiredRoot.cert()))
                .failureReason())
        .hasValue("Leaf certificate must not be a CA");
  }

  @Test
  void testValidateCertificateChain_untrustedIncompleteAndForgedChains_rejected() throws Exception {
    // Leaf issued by an untrusted CA.
    X509Certificate untrustedLeaf =
        signLeaf(untrustedCa, generateKeyPair(), "epp.untrusted.example");
    CertificateChainValidationResult untrustedResult =
        assertChainInvalid(new Certificate[] {untrustedLeaf}, rootTrustManager);
    assertThat(untrustedResult.failureReason().get()).contains("PKIX path building failed");
    assertChainInvalid(new Certificate[] {untrustedLeaf, untrustedCa.cert()}, rootTrustManager);

    // Missing intermediate CA in a 3-tier chain.
    KeyPair intermediateKeyPair = generateKeyPair();
    X509Certificate intermediateCa =
        signIntermediateCa(
            rootCa.key(),
            rootCa.cert(),
            intermediateKeyPair,
            "intermediate-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(true));
    X509Certificate threeTierLeaf =
        signLeaf(
            intermediateKeyPair.getPrivate(),
            intermediateCa,
            generateKeyPair(),
            "epp.three-tier.example",
            VALID_FROM,
            VALID_TO);
    assertChainInvalid(new Certificate[] {threeTierLeaf}, rootTrustManager);
    assertChainInvalid(new Certificate[] {threeTierLeaf, untrustedCa.cert()}, rootTrustManager);

    // Forged signature: claims rootCa issuer DN, signed with untrustedCa's private key.
    X509Certificate forgedSigLeaf =
        signLeaf(
            untrustedCa.key(),
            rootCa.cert(),
            generateKeyPair(),
            "epp.forged.example",
            VALID_FROM,
            VALID_TO);
    assertChainInvalid(new Certificate[] {forgedSigLeaf}, rootTrustManager);

    // Self-signed non-CA leaf (BasicConstraints: cA=false) fails PKIX path building rather than
    // the CA-as-leaf guard.
    KeyPair selfSignedLeafKey = generateKeyPair();
    X509v3CertificateBuilder selfSignedLeafBuilder =
        new JcaX509v3CertificateBuilder(
            new X500Name("CN=epp.selfsigned-leaf.example"),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=epp.selfsigned-leaf.example"),
            selfSignedLeafKey.getPublic());
    selfSignedLeafBuilder.addExtension(
        Extension.basicConstraints, true, new BasicConstraints(false));
    X509Certificate selfSignedNonCaLeaf =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                selfSignedLeafBuilder.build(
                    new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                        .build(selfSignedLeafKey.getPrivate())));
    CertificateChainValidationResult selfSignedResult =
        assertChainInvalid(new Certificate[] {selfSignedNonCaLeaf}, rootTrustManager);
    assertThat(selfSignedResult.failureReason().get()).contains("PKIX path building failed");
  }

  @Test
  void testValidateCertificateChain_expiredAndNotYetValid_rejected() throws Exception {
    X509Certificate expiredLeaf =
        signLeaf(
            rootCa.key(),
            rootCa.cert(),
            generateKeyPair(),
            "epp.expired.example",
            EXPIRED_FROM,
            EXPIRED_TO);
    assertThat(
            assertChainInvalid(new Certificate[] {expiredLeaf}, rootTrustManager)
                .failureReason()
                .get())
        .startsWith("CertificateExpiredException:");

    X509Certificate notYetValidLeaf =
        signLeaf(
            rootCa.key(),
            rootCa.cert(),
            generateKeyPair(),
            "epp.future.example",
            FUTURE_FROM,
            FUTURE_TO);
    assertThat(
            assertChainInvalid(new Certificate[] {notYetValidLeaf}, rootTrustManager)
                .failureReason()
                .get())
        .startsWith("CertificateNotYetValidException:");

    // Expired and not-yet-valid NON-CA leaves pinned directly as trust anchors (0-length path)
    // must still be rejected by the explicit leafCert.checkValidity() guard.
    assertThat(
            assertChainInvalid(new Certificate[] {expiredLeaf}, createTrustManager(expiredLeaf))
                .failureReason()
                .get())
        .startsWith("CertificateExpiredException:");
    assertThat(
            assertChainInvalid(
                    new Certificate[] {notYetValidLeaf}, createTrustManager(notYetValidLeaf))
                .failureReason()
                .get())
        .startsWith("CertificateNotYetValidException:");

    // Expired and not-yet-valid intermediate CAs with a currently valid leaf.
    KeyPair expiredInterKeyPair = generateKeyPair();
    X509Certificate expiredIntermediate =
        signIntermediateCa(
            rootCa.key(),
            rootCa.cert(),
            expiredInterKeyPair,
            "expired-intermediate.tld",
            EXPIRED_FROM,
            EXPIRED_TO,
            new BasicConstraints(true));
    X509Certificate leafUnderExpiredInter =
        signLeaf(
            expiredInterKeyPair.getPrivate(),
            expiredIntermediate,
            generateKeyPair(),
            "epp.expired-inter.example",
            VALID_FROM,
            VALID_TO);
    assertChainInvalid(
        new Certificate[] {leafUnderExpiredInter, expiredIntermediate}, rootTrustManager);

    KeyPair futureInterKeyPair = generateKeyPair();
    X509Certificate futureIntermediate =
        signIntermediateCa(
            rootCa.key(),
            rootCa.cert(),
            futureInterKeyPair,
            "future-intermediate.tld",
            FUTURE_FROM,
            FUTURE_TO,
            new BasicConstraints(true));
    X509Certificate leafUnderFutureInter =
        signLeaf(
            futureInterKeyPair.getPrivate(),
            futureIntermediate,
            generateKeyPair(),
            "epp.future-inter.example",
            VALID_FROM,
            VALID_TO);
    assertChainInvalid(
        new Certificate[] {leafUnderFutureInter, futureIntermediate}, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_constraintViolations_rejected() throws Exception {
    // Leaf-acting-as-CA forgery: a valid non-CA leaf signs another certificate.
    KeyPair nonCaLeafKeyPair = generateKeyPair();
    X509Certificate validNonCaLeaf = signLeaf(rootCa, nonCaLeafKeyPair, "attacker.example");
    X509Certificate forgedLeaf =
        signLeaf(
            nonCaLeafKeyPair.getPrivate(),
            validNonCaLeaf,
            generateKeyPair(),
            "victim.example",
            VALID_FROM,
            VALID_TO);
    assertChainInvalid(new Certificate[] {forgedLeaf, validNonCaLeaf}, rootTrustManager);

    // Path length constraint violation: pathLenConstraint=0 intermediate signs a sub-CA.
    KeyPair pathLen0KeyPair = generateKeyPair();
    X509Certificate pathLen0Intermediate =
        signIntermediateCa(
            rootCa.key(),
            rootCa.cert(),
            pathLen0KeyPair,
            "pathlen0-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(0));
    KeyPair subCaKeyPair = generateKeyPair();
    X509Certificate subCa =
        signIntermediateCa(
            pathLen0KeyPair.getPrivate(),
            pathLen0Intermediate,
            subCaKeyPair,
            "sub-ca.tld",
            VALID_FROM,
            VALID_TO,
            new BasicConstraints(true));
    X509Certificate leafUnderSubCa =
        signLeaf(
            subCaKeyPair.getPrivate(),
            subCa,
            generateKeyPair(),
            "epp.sub.example",
            VALID_FROM,
            VALID_TO);
    assertChainInvalid(
        new Certificate[] {leafUnderSubCa, subCa, pathLen0Intermediate}, rootTrustManager);

    // Intermediate CA with KeyUsage extension missing keyCertSign must fail PKIX validation.
    KeyPair noKeyCertSignKeyPair = generateKeyPair();
    X509Certificate noKeyCertSignInter =
        signIntermediateCaWithKeyUsage(
            rootCa,
            noKeyCertSignKeyPair,
            "no-certsign-ca.tld",
            new KeyUsage(KeyUsage.digitalSignature));
    X509Certificate leafUnderNoCertSign =
        signLeaf(
            noKeyCertSignKeyPair.getPrivate(),
            noKeyCertSignInter,
            generateKeyPair(),
            "epp.nocertsign.example",
            VALID_FROM,
            VALID_TO);
    assertChainInvalid(
        new Certificate[] {leafUnderNoCertSign, noKeyCertSignInter}, rootTrustManager);

    // NameConstraints violation on intermediate CA must be rejected.
    KeyPair ncInterKeyPair = generateKeyPair();
    X509v3CertificateBuilder ncInterBuilder =
        new JcaX509v3CertificateBuilder(
            X500Name.getInstance(rootCa.cert().getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=nc-restricted.tld"),
            ncInterKeyPair.getPublic());
    ncInterBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    ncInterBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
    ncInterBuilder.addExtension(
        Extension.nameConstraints,
        true,
        new NameConstraints(
            new GeneralSubtree[] {
              new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".allowed.example"))
            },
            null));
    X509Certificate ncInter =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                ncInterBuilder.build(
                    new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootCa.key())));
    X509Certificate disallowedNcLeaf =
        signLeaf(
            ncInterKeyPair.getPrivate(),
            ncInter,
            generateKeyPair(),
            "epp.disallowed.example",
            VALID_FROM,
            VALID_TO,
            "epp.disallowed.example");
    CertificateChainValidationResult ncResult =
        assertChainInvalid(new Certificate[] {disallowedNcLeaf, ncInter}, rootTrustManager);
    assertThat(ncResult.failureReason().get()).contains("name constraints");

    // Unrecognized critical extension on leaf must fail PKIX validation (RFC 5280 sec. 4.2).
    X509v3CertificateBuilder unknownCritBuilder =
        new JcaX509v3CertificateBuilder(
            X500Name.getInstance(rootCa.cert().getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=epp.unknowncrit.example"),
            generateKeyPair().getPublic());
    unknownCritBuilder.addExtension(
        new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.9"), true, DERNull.INSTANCE);
    X509Certificate unknownCritLeaf =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                unknownCritBuilder.build(
                    new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootCa.key())));
    CertificateChainValidationResult unknownCritResult =
        assertChainInvalid(new Certificate[] {unknownCritLeaf}, rootTrustManager);
    assertThat(unknownCritResult.failureReason().get()).contains("critical extension");
  }

  @Test
  void testValidateCertificateChain_disallowedAndMalformedExtendedKeyUsages_rejected()
      throws Exception {
    // clientAuth-only and non-TLS ExtendedKeyUsage leaves must all be rejected by
    // checkServerTrusted even when signed by a trusted CA.
    for (KeyPurposeId disallowedPurpose :
        ImmutableList.of(
            KeyPurposeId.id_kp_clientAuth,
            KeyPurposeId.id_kp_codeSigning,
            KeyPurposeId.id_kp_emailProtection,
            KeyPurposeId.id_kp_timeStamping,
            KeyPurposeId.id_kp_OCSPSigning)) {
      X509Certificate leaf =
          signLeafWithEku(
              rootCa,
              generateKeyPair(),
              "epp.disallowed-eku.example",
              new ExtendedKeyUsage(disallowedPurpose),
              "epp.disallowed-eku.example");
      CertificateChainValidationResult result =
          assertChainInvalid(new Certificate[] {leaf}, rootTrustManager);
      assertThat(result.failureReason().get()).contains("Extended key usage");
    }

    // Mixed clientAuth + emailProtection (no serverAuth/anyExtendedKeyUsage) must be rejected.
    X509Certificate clientAuthPlusEmailLeaf =
        signLeafWithEku(
            rootCa,
            generateKeyPair(),
            "epp.clientauth-email.example",
            new ExtendedKeyUsage(
                new KeyPurposeId[] {
                  KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection
                }),
            "epp.clientauth-email.example");
    assertThat(
            assertChainInvalid(new Certificate[] {clientAuthPlusEmailLeaf}, rootTrustManager)
                .failureReason()
                .get())
        .contains("Extended key usage");

    // Malformed EKU extension must fail closed, never throw.
    X509v3CertificateBuilder malformedEkuBuilder =
        new JcaX509v3CertificateBuilder(
            X500Name.getInstance(rootCa.cert().getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=epp.malformed-eku.example"),
            generateKeyPair().getPublic());
    malformedEkuBuilder.addExtension(
        Extension.extendedKeyUsage, false, new byte[] {0x01, 0x02, 0x03});
    X509Certificate malformedEkuLeaf =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                malformedEkuBuilder.build(
                    new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootCa.key())));
    assertChainInvalid(new Certificate[] {malformedEkuLeaf}, rootTrustManager);

    // Degenerate empty-SEQUENCE EKU extension must fail closed.
    X509v3CertificateBuilder emptyEkuBuilder =
        new JcaX509v3CertificateBuilder(
            X500Name.getInstance(rootCa.cert().getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=epp.empty-eku.example"),
            generateKeyPair().getPublic());
    emptyEkuBuilder.addExtension(Extension.extendedKeyUsage, false, new DERSequence());
    X509Certificate emptyEkuLeaf =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                emptyEkuBuilder.build(
                    new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rootCa.key())));
    assertChainInvalid(new Certificate[] {emptyEkuLeaf}, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_missingDigitalSignatureKeyUsage_rejected() throws Exception {
    for (int keyUsageBits :
        ImmutableList.of(
            KeyUsage.cRLSign,
            KeyUsage.keyEncipherment,
            KeyUsage.keyAgreement,
            KeyUsage.keyCertSign)) {
      X509Certificate rsaLeaf =
          signLeafWithExtensions(
              rootCa,
              generateKeyPair(),
              "epp.badku.example",
              new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
              new KeyUsage(keyUsageBits),
              "epp.badku.example");
      assertChainInvalid(new Certificate[] {rsaLeaf}, rootTrustManager);
    }

    X509Certificate ecCrlSignLeaf =
        signLeafWithExtensions(
            rootCa,
            generateEcKeyPair(),
            "epp.eccrlsign.example",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
            new KeyUsage(KeyUsage.cRLSign),
            "epp.eccrlsign.example");
    assertChainInvalid(new Certificate[] {ecCrlSignLeaf}, rootTrustManager);

    X509Certificate ed25519CrlSignLeaf =
        signLeafWithExtensions(
            rootCa,
            generateEd25519KeyPair(),
            "epp.edcrlsign.example",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
            new KeyUsage(KeyUsage.cRLSign),
            "epp.edcrlsign.example");
    assertChainInvalid(new Certificate[] {ed25519CrlSignLeaf}, rootTrustManager);
  }

  @Test
  void testValidateCertificateChain_weakSignatureAlgorithm_rejected() throws Exception {
    // Weak/disabled signature algorithm (MD5WithRSA) must be rejected by JDK algorithm constraints.
    X509v3CertificateBuilder md5LeafBuilder =
        new JcaX509v3CertificateBuilder(
            X500Name.getInstance(rootCa.cert().getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(SERIAL_NUMBER.incrementAndGet()),
            toAsn1Time(VALID_FROM),
            toAsn1Time(VALID_TO),
            new X500Name("CN=epp.md5.example"),
            generateKeyPair().getPublic());
    X509Certificate md5Leaf =
        new JcaX509CertificateConverter()
            .setProvider(PROVIDER)
            .getCertificate(
                md5LeafBuilder.build(
                    new JcaContentSignerBuilder("MD5WithRSA").build(rootCa.key())));
    CertificateChainValidationResult md5Result =
        assertChainInvalid(new Certificate[] {md5Leaf}, rootTrustManager);
    assertThat(md5Result.failureReason().get()).contains("MD5");
  }

  @Test
  void testValidateCertificateChain_runtimeExceptions_failClosedWithoutThrowing() throws Exception {
    // Simulates Netty's LazyX509Certificate.unwrap() throwing IllegalStateException on malformed
    // DER when getBasicConstraints() is invoked on the leaf.
    X509Certificate brokenLeaf = mock(X509Certificate.class);
    when(brokenLeaf.getBasicConstraints())
        .thenThrow(new IllegalStateException(new CertificateException("malformed DER")));
    CertificateChainValidationResult leafRuntimeResult =
        assertChainInvalid(new Certificate[] {brokenLeaf}, rootTrustManager);
    assertThat(leafRuntimeResult.failureReason().get()).startsWith("IllegalStateException:");

    // Simulates a LazyX509Certificate intermediate throwing IllegalStateException or a
    // TrustManager throwing ProviderException during checkServerTrusted().
    X509Certificate directLeaf = signLeaf(rootCa, generateKeyPair(), "epp.runtime.example");
    X509TrustManager illegalStateTm = mock(X509TrustManager.class);
    doThrow(new IllegalStateException("failed to parse intermediate DER"))
        .when(illegalStateTm)
        .checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
    assertThat(assertChainInvalid(new Certificate[] {directLeaf}, illegalStateTm).failureReason())
        .hasValue("IllegalStateException: failed to parse intermediate DER");

    X509TrustManager providerExceptionTm = mock(X509TrustManager.class);
    doThrow(new ProviderException("provider failure"))
        .when(providerExceptionTm)
        .checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
    assertThat(
            assertChainInvalid(new Certificate[] {directLeaf}, providerExceptionTm).failureReason())
        .hasValue("ProviderException: provider failure");
  }

  @Test
  void testValidateCertificateChain_sanitizesAndBoundsFailureReason() throws Exception {
    X509Certificate directLeaf = signLeaf(rootCa, generateKeyPair(), "epp.sanitize.example");

    // Null, empty, and control-char-only messages fall back to exception class name (no colon).
    for (String blankMessage : Arrays.asList(null, "", "   ", "\r\n\t")) {
      X509TrustManager mockTm = mock(X509TrustManager.class);
      doThrow(new CertificateException(blankMessage))
          .when(mockTm)
          .checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
      assertThat(assertChainInvalid(new Certificate[] {directLeaf}, mockTm).failureReason())
          .hasValue("CertificateException");
    }

    // Anonymous exception subclass with null message still produces a non-blank failure reason.
    X509TrustManager anonTm = mock(X509TrustManager.class);
    doThrow(new CertificateException() {})
        .when(anonTm)
        .checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
    assertThat(assertChainInvalid(new Certificate[] {directLeaf}, anonTm).failureReason().get())
        .contains(X509UtilsTest.class.getName());

    // Control characters (\r, \n, \t) in untrusted PKIX messages are collapsed to spaces.
    X509TrustManager logInjectionTm = mock(X509TrustManager.class);
    doThrow(new CertificateException("Bad DN\r\nClient Certificate Chain Validated: true\tForged"))
        .when(logInjectionTm)
        .checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
    String sanitizedReason =
        assertChainInvalid(new Certificate[] {directLeaf}, logInjectionTm).failureReason().get();
    assertThat(sanitizedReason).doesNotContain("\r");
    assertThat(sanitizedReason).doesNotContain("\n");
    assertThat(sanitizedReason).doesNotContain("\t");
    assertThat(sanitizedReason)
        .isEqualTo("CertificateException: Bad DN  Client Certificate Chain Validated: true Forged");

    // Overlong exception messages are capped at 512 characters with an ellipsis suffix.
    X509TrustManager overlongTm = mock(X509TrustManager.class);
    doThrow(new CertificateException("x".repeat(1000)))
        .when(overlongTm)
        .checkServerTrusted(any(X509Certificate[].class), eq("UNKNOWN"));
    String truncatedReason =
        assertChainInvalid(new Certificate[] {directLeaf}, overlongTm).failureReason().get();
    assertThat(truncatedReason).hasLength(512);
    assertThat(truncatedReason).endsWith("...");
  }

  @Test
  void testExtractHostnames_dnsSansCanonicalizationAndWildcards() throws Exception {
    // Mixed case, trailing dot, duplicates, punycode A-label, and valid single-label wildcards.
    X509Certificate dnsSanCert =
        signLeaf(
            rootCa,
            generateKeyPair(),
            "Ignored.CN.Example",
            "EPP1.Example.TLD.",
            "epp1.example.tld",
            "XN--Q9JYB4C.Example.COM",
            "*.Example.COM",
            "*.Example.COM.",
            "*.Sub.Example.COM",
            "*.XN--Q9JYB4C.Example");
    assertThat(extractHostnames(dnsSanCert))
        .containsExactly(
            "epp1.example.tld",
            "xn--q9jyb4c.example.com",
            "*.example.com",
            "*.sub.example.com",
            "*.xn--q9jyb4c.example")
        .inOrder();

    // Max-length valid hostname (253 chars) and max-length valid wildcard (253 chars).
    String maxHostname =
        "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61);
    String maxWildcard =
        "*." + "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(59);
    assertThat(maxHostname).hasLength(253);
    assertThat(maxWildcard).hasLength(253);
    X509Certificate maxLenCert =
        signLeaf(rootCa, generateKeyPair(), "ignored.example", maxHostname, maxWildcard);
    assertThat(extractHostnames(maxLenCert)).containsExactly(maxHostname, maxWildcard).inOrder();

    // Mixed valid and invalid DNS SANs with a valid CN: valid DNS SANs kept, CN still ignored.
    X509Certificate mixedSanCert =
        signLeaf(
            rootCa,
            generateKeyPair(),
            "ignored.cn.example",
            "*.com",
            "epp.valid.example",
            "bad_host.example",
            "*.valid.example",
            "192.0.2.1");
    assertThat(extractHostnames(mixedSanCert))
        .containsExactly("epp.valid.example", "*.valid.example")
        .inOrder();

    // Mixed non-DNS SAN types (IP, email, URI) alongside valid DNS SANs: only DNS SANs extracted.
    X509Certificate mixedSanTypesCert =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            "CN=ignored.cn.example",
            new GeneralName(GeneralName.iPAddress, "192.0.2.1"),
            new GeneralName(GeneralName.rfc822Name, "ops@example.tld"),
            new GeneralName(GeneralName.uniformResourceIdentifier, "https://epp.example.tld"),
            new GeneralName(GeneralName.dNSName, "epp.mixed-types.example"));
    assertThat(extractHostnames(mixedSanTypesCert)).containsExactly("epp.mixed-types.example");

    // Malformed SAN list entries (null, short list, non-String value) are ignored while valid ones
    // are kept.
    X509Certificate certWithMalformedSanEntries = mock(X509Certificate.class);
    List<List<?>> mixedMalformedSans =
        Arrays.asList(
            null,
            ImmutableList.of(GeneralName.dNSName),
            ImmutableList.of(GeneralName.dNSName, new byte[] {1, 2, 3}),
            ImmutableList.of(GeneralName.dNSName, "valid.example.tld"));
    when(certWithMalformedSanEntries.getSubjectAlternativeNames()).thenReturn(mixedMalformedSans);
    assertThat(extractHostnames(certWithMalformedSanEntries)).containsExactly("valid.example.tld");
  }

  @Test
  void testExtractHostnames_cnFallbackWhenNoSanExtension() throws Exception {
    X509Certificate cnFallbackCert =
        signLeafWithGeneralNames(rootCa, generateKeyPair(), "CN=EPP.Fallback.Example.");
    assertThat(extractHostnames(cnFallbackCert)).containsExactly("epp.fallback.example");

    X509Certificate wildcardCnCert =
        signLeafWithGeneralNames(rootCa, generateKeyPair(), "CN=*.Fallback.Example");
    assertThat(extractHostnames(wildcardCnCert)).containsExactly("*.fallback.example");

    X509Certificate unicodeCnCert =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "epp.みんな").build());
    assertThat(extractHostnames(unicodeCnCert)).containsExactly("epp.xn--q9jyb4c");

    X509Certificate wildcardUnicodeCnCert =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "*.みんな.example").build());
    assertThat(extractHostnames(wildcardUnicodeCnCert)).containsExactly("*.xn--q9jyb4c.example");

    // Empty (non-null) SAN collection with no SAN extension falls back to Subject CN.
    X509Certificate emptySanCollectionCert = mock(X509Certificate.class);
    when(emptySanCollectionCert.getSubjectAlternativeNames()).thenReturn(ImmutableList.of());
    when(emptySanCollectionCert.getSubjectX500Principal())
        .thenReturn(new X500Principal("CN=empty-san.example.tld"));
    assertThat(extractHostnames(emptySanCollectionCert)).containsExactly("empty-san.example.tld");

    // Multi-valued RDN containing CN, multiple CN RDNs with duplicates, and mixed org+host CNs.
    X509Certificate multiValuedRdnCert =
        signLeafWithGeneralNames(rootCa, generateKeyPair(), "O=Example+CN=epp.multivalue.example");
    assertThat(extractHostnames(multiValuedRdnCert)).containsExactly("epp.multivalue.example");

    X509Certificate multiCnCert =
        signLeafWithGeneralNames(
            rootCa, generateKeyPair(), "CN=a.example,CN=A.EXAMPLE,CN=b.example");
    assertThat(extractHostnames(multiCnCert)).containsExactly("a.example", "b.example").inOrder();

    X509Certificate mixedValidAndInvalidCnCert =
        signLeafWithGeneralNames(rootCa, generateKeyPair(), "CN=Acme Corp,CN=epp.valid-cn.example");
    assertThat(extractHostnames(mixedValidAndInvalidCnCert))
        .containsExactly("epp.valid-cn.example");
  }

  @Test
  void testExtractHostnames_sanExtensionSuppressesCnFallback() throws Exception {
    // RFC 9525 section 6.2: any SAN extension suppresses CN fallback, even without valid DNS SANs.
    X509Certificate certWithIpSanOnly =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            "CN=fallback.example.tld",
            new GeneralName(GeneralName.iPAddress, "192.0.2.1"));
    assertThat(extractHostnames(certWithIpSanOnly)).isEmpty();

    X509Certificate certWithEmailSanOnly =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            "CN=fallback.example.tld",
            new GeneralName(GeneralName.rfc822Name, "ops@example.tld"));
    assertThat(extractHostnames(certWithEmailSanOnly)).isEmpty();

    X509Certificate certWithUriSanOnly =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            "CN=fallback.example.tld",
            new GeneralName(GeneralName.uniformResourceIdentifier, "https://epp.example.tld"));
    assertThat(extractHostnames(certWithUriSanOnly)).isEmpty();

    X509Certificate certWithOnlyInvalidDnsSans =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            "CN=fallback.example.tld",
            new GeneralName(GeneralName.dNSName, "   "),
            new GeneralName(GeneralName.dNSName, "*.com"));
    assertThat(extractHostnames(certWithOnlyInvalidDnsSans)).isEmpty();

    // Degenerate empty-SEQUENCE SAN extension still suppresses CN fallback per RFC 9525 sec. 6.2.
    X509Certificate emptySanSequenceCert =
        signLeafWithEmptySanSequence(rootCa, generateKeyPair(), "CN=fallback.example.tld");
    assertThat(emptySanSequenceCert.getExtensionValue(Extension.subjectAlternativeName.getId()))
        .isNotNull();
    assertThat(extractHostnames(emptySanSequenceCert)).isEmpty();

    // Present SAN extension whose parsed collection is empty (non-null) also suppresses CN.
    X509Certificate presentEmptySanCert = mock(X509Certificate.class);
    when(presentEmptySanCert.getExtensionValue(Extension.subjectAlternativeName.getId()))
        .thenReturn(new byte[] {0x04, 0x02, 0x30, 0x00});
    when(presentEmptySanCert.getSubjectAlternativeNames()).thenReturn(ImmutableList.of());
    assertThat(extractHostnames(presentEmptySanCert)).isEmpty();

    // Malformed SAN extension throws CertificateParsingException -> fail closed, no CN fallback.
    X509Certificate malformedSanCert =
        signLeafWithMalformedSanExtension(rootCa, generateKeyPair(), "CN=fallback.example.tld");
    assertThrows(CertificateParsingException.class, malformedSanCert::getSubjectAlternativeNames);
    assertThat(extractHostnames(malformedSanCert)).isEmpty();
  }

  @Test
  void testExtractHostnames_rejectsWildcardsOverPublicSuffixes() throws Exception {
    ImmutableList<String> publicSuffixWildcards =
        ImmutableList.of(
            "*.co.uk",
            "*.com.au",
            "*.gov.uk",
            "*.appspot.com",
            "*.s3.amazonaws.com",
            "*.github.io");
    X509Certificate sanCert =
        signLeaf(
            rootCa,
            generateKeyPair(),
            "ignored.example",
            "*.co.uk",
            "*.com.au",
            "*.gov.uk",
            "*.appspot.com",
            "*.s3.amazonaws.com",
            "*.github.io",
            "*.registrar.co.uk",
            "*.example.com",
            "*.example.tld",
            "*.myapp.appspot.com",
            "co.uk",
            "appspot.com");
    assertThat(extractHostnames(sanCert))
        .containsExactly(
            "*.registrar.co.uk",
            "*.example.com",
            "*.example.tld",
            "*.myapp.appspot.com",
            "co.uk",
            "appspot.com")
        .inOrder();

    for (String disallowedWildcard : publicSuffixWildcards) {
      X509Certificate cnCert =
          signLeafWithGeneralNames(rootCa, generateKeyPair(), "CN=" + disallowedWildcard);
      assertThat(extractHostnames(cnCert)).isEmpty();
    }
  }

  @Test
  void testExtractHostnames_rejectsInvalidDnsSansAndCns() throws Exception {
    ImmutableList<String> invalidDnsValues =
        ImmutableList.of(
            "",
            "   ",
            ".",
            "localhost",
            "localhost.",
            ".example.com",
            "epp..example.com",
            "epp.example.com..",
            "*",
            "*.",
            "*.com",
            "*.com.",
            "*..example.com",
            "*.*.example.com",
            "a*.example.com",
            "*a.example.com",
            "epp.*.example.com",
            "192.0.2.1",
            "2001:db8::1",
            "epp_1.example.com",
            "-epp.example.com",
            "epp-.example.com",
            "ab--cd.example.com",
            " epp.example.com",
            "epp.example.com ",
            "https://epp.example.com",
            "epp.example.com:700",
            "evil.example\r\nX-Injected: 1",
            "evil.example\nfoo",
            "epp.example.tld\0.evil.com",
            "a.example,b.example",
            "a".repeat(64) + ".example",
            "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(62),
            "*."
                + "a".repeat(63)
                + "."
                + "b".repeat(63)
                + "."
                + "c".repeat(63)
                + "."
                + "d".repeat(60));
    X509Certificate invalidDnsSanCert =
        signLeaf(
            rootCa, generateKeyPair(), "ignored.example", invalidDnsValues.toArray(new String[0]));
    assertThat(extractHostnames(invalidDnsSanCert)).isEmpty();

    for (String invalidCn :
        ImmutableList.of(
            "",
            "   ",
            "Acme, Inc.",
            "a.example,b.example",
            "evil.example\r\nX-Injected: 1",
            "epp.example.tld\0.evil.com",
            "localhost",
            "*.com",
            "192.0.2.1",
            "epp_1.example.com",
            "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(62),
            "*."
                + "a".repeat(63)
                + "."
                + "b".repeat(63)
                + "."
                + "c".repeat(63)
                + "."
                + "d".repeat(60))) {
      X509Certificate invalidCnCert =
          signLeafWithGeneralNames(
              rootCa,
              generateKeyPair(),
              new X500NameBuilder(BCStyle.INSTANCE)
                  .addRDN(BCStyle.CN, new DERUTF8String(invalidCn))
                  .build());
      assertThat(extractHostnames(invalidCnCert)).isEmpty();
    }
  }

  @Test
  void testExtractHostnames_handlesNullNonStringCnAndRuntimeExceptions() throws Exception {
    assertThrows(NullPointerException.class, () -> extractHostnames(null));

    // Subject with no CN and no SAN extension.
    X509Certificate certWithoutCnOrSans =
        signLeafWithGeneralNames(rootCa, generateKeyPair(), "O=Example");
    assertThat(extractHostnames(certWithoutCnOrSans)).isEmpty();

    // Null Subject principal and RuntimeException while parsing Subject DN both return empty.
    X509Certificate certWithNullPrincipal = mock(X509Certificate.class);
    when(certWithNullPrincipal.getSubjectAlternativeNames()).thenReturn(null);
    when(certWithNullPrincipal.getSubjectX500Principal()).thenReturn(null);
    assertThat(extractHostnames(certWithNullPrincipal)).isEmpty();

    X509Certificate certWithCorruptPrincipal = mock(X509Certificate.class);
    X500Principal corruptPrincipal = mock(X500Principal.class);
    when(certWithCorruptPrincipal.getSubjectAlternativeNames()).thenReturn(null);
    when(certWithCorruptPrincipal.getSubjectX500Principal()).thenReturn(corruptPrincipal);
    when(corruptPrincipal.getEncoded()).thenReturn(new byte[] {0x01, 0x02, 0x03});
    assertThat(extractHostnames(certWithCorruptPrincipal)).isEmpty();

    // Non-string ASN.1 CN values (DERSequence, DEROctetString) are ignored without crashing.
    X509Certificate sequenceCnCert =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, new DERSequence()).build());
    assertThat(extractHostnames(sequenceCnCert)).isEmpty();

    X509Certificate octetStringCnCert =
        signLeafWithGeneralNames(
            rootCa,
            generateKeyPair(),
            new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, new DEROctetString(new byte[] {1, 2, 3}))
                .build());
    assertThat(extractHostnames(octetStringCnCert)).isEmpty();

    // LazyX509Certificate-style RuntimeExceptions during SAN or Subject lookup fail closed.
    X509Certificate throwingSanCert = mock(X509Certificate.class);
    when(throwingSanCert.getSubjectAlternativeNames())
        .thenThrow(new IllegalStateException("malformed DER"));
    assertThat(extractHostnames(throwingSanCert)).isEmpty();

    X509Certificate throwingPrincipalCert = mock(X509Certificate.class);
    when(throwingPrincipalCert.getSubjectAlternativeNames()).thenReturn(null);
    when(throwingPrincipalCert.getSubjectX500Principal())
        .thenThrow(new IllegalStateException("malformed DER"));
    assertThat(extractHostnames(throwingPrincipalCert)).isEmpty();
  }

  @Test
  void testFormatHostnamesHeader_nullEmptyAndBlankFiltering() {
    assertThat(formatHostnamesHeader(null, "cert-hash")).isNull();
    assertThat(formatHostnamesHeader(ImmutableList.of(), "cert-hash")).isNull();
    assertThat(formatHostnamesHeader(ImmutableList.of(""), "cert-hash")).isNull();
    assertThat(formatHostnamesHeader(ImmutableList.of("   "), "cert-hash")).isNull();
    assertThat(formatHostnamesHeader(ImmutableList.of("", "a.tld", "  ", "b.tld"), "cert-hash"))
        .isEqualTo("a.tld,b.tld");
    assertThat(
            formatHostnamesHeader(
                ImmutableList.of("a.tld", "b.tld"), Integer.MAX_VALUE, "cert-hash"))
        .isEqualTo("a.tld,b.tld");
    assertThat(formatHostnamesHeader(ImmutableList.of("epp.example.tld"), "cert-hash"))
        .isEqualTo("epp.example.tld");
    assertThat(
            formatHostnamesHeader(
                ImmutableList.of("epp1.example.tld", "epp2.example.tld"), "cert-hash"))
        .isEqualTo("epp1.example.tld,epp2.example.tld");
  }

  @Test
  void testFormatHostnamesHeader_exactBoundariesAndUtf8Bytes() {
    // Exact boundary fits; one byte smaller truncates cleanly on a whole-hostname boundary.
    ImmutableList<String> twoHosts = ImmutableList.of("a.tld", "b.tld");
    assertThat(formatHostnamesHeader(twoHosts, 11, "cert-hash")).isEqualTo("a.tld,b.tld");
    assertThat(formatHostnamesHeader(twoHosts, 10, "cert-hash")).isEqualTo("a.tld");
    assertThat(formatHostnamesHeader(twoHosts, 5, "cert-hash")).isEqualTo("a.tld");
    // Even the first hostname exceeds maxBytes -> returns null rather than empty string.
    assertThat(formatHostnamesHeader(twoHosts, 4, "cert-hash")).isNull();

    assertThrows(
        IllegalArgumentException.class, () -> formatHostnamesHeader(twoHosts, 0, "cert-hash"));
    assertThrows(
        IllegalArgumentException.class, () -> formatHostnamesHeader(twoHosts, -1, "cert-hash"));

    // UTF-8 byte counting (not UTF-16 char count): each CJK char is 3 bytes in UTF-8.
    assertThat(formatHostnamesHeader(ImmutableList.of("みんな", "a.tld"), 9, "cert-hash"))
        .isEqualTo("みんな");
    assertThat(formatHostnamesHeader(ImmutableList.of("みんな", "a.tld"), 8, "cert-hash")).isNull();

    // Exact MAX_HOSTNAMES_HEADER_BYTES (4096) fits completely without truncation; 4097 truncates.
    // 127 * 31 + 32 + 127 commas = 4096 bytes.
    ImmutableList<String> exactMaxHostnames =
        IntStream.range(0, 128)
            .mapToObj(
                i ->
                    i == 127
                        ? String.format("epp-host-%03d.reg-last.example.tl", i)
                        : String.format("epp-host-%03d.reg-pad.example.tl", i))
            .collect(ImmutableList.toImmutableList());
    String exactFormatted = formatHostnamesHeader(exactMaxHostnames, "cert-hash");
    assertThat(exactFormatted).isNotNull();
    assertThat(exactFormatted).hasLength(MAX_HOSTNAMES_HEADER_BYTES);
    assertThat(Splitter.on(',').splitToList(exactFormatted)).isEqualTo(exactMaxHostnames);

    ImmutableList<String> oneByteOverHostnames =
        ImmutableList.<String>builder().addAll(exactMaxHostnames).add("x").build();
    assertThat(formatHostnamesHeader(oneByteOverHostnames, "cert-hash")).isEqualTo(exactFormatted);

    // Realistic oversized multi-SAN UCC cert (300 hostnames) is cleanly capped at 4096 bytes.
    ImmutableList<String> oversizedHostnames =
        IntStream.range(0, 300)
            .mapToObj(i -> String.format("epp-host-%03d.registrar.example.tld", i))
            .collect(ImmutableList.toImmutableList());
    String formatted = formatHostnamesHeader(oversizedHostnames, "cert-hash");
    assertThat(formatted).isNotNull();
    assertThat(formatted.length()).isAtMost(MAX_HOSTNAMES_HEADER_BYTES);
    assertThat(formatted).doesNotMatch("^,|,$");
    List<String> included = Splitter.on(',').splitToList(formatted);
    assertThat(included).hasSize(117);
    assertThat(included).isEqualTo(oversizedHostnames.subList(0, included.size()));
    assertThat(formatted.length() + 1 + oversizedHostnames.get(included.size()).length())
        .isGreaterThan(MAX_HOSTNAMES_HEADER_BYTES);
  }

  @Test
  void testFormatHostnamesHeader_truncationLogsCertHashAndAccurateNonBlankCount() {
    Logger logger = Logger.getLogger(X509Utils.class.getName());
    TestLogHandler logHandler = new TestLogHandler();
    logger.addHandler(logHandler);
    try {
      // Blank entries skipped before counting so log reports 2 hostnames, not 4.
      assertThat(
              formatHostnamesHeader(ImmutableList.of("", "a.tld", "  ", "b.tld"), 5, "abc123hash"))
          .isEqualTo("a.tld");
      assertThat(formatHostnamesHeader(ImmutableList.of("a.tld", "b.tld"), 5, null))
          .isEqualTo("a.tld");

      ImmutableList<LogRecord> warnings =
          logHandler.getStoredLogRecords().stream()
              .filter(record -> record.getLevel().equals(Level.WARNING))
              .collect(ImmutableList.toImmutableList());
      assertThat(warnings).hasSize(2);
      assertThat(warnings.get(0).getMessage())
          .isEqualTo(
              "Client certificate (hash=abc123hash) has 2 hostnames; truncating"
                  + " X-SSL-Certificate-Hostnames header to 1 hostnames (<= 5 bytes).");
      assertThat(warnings.get(1).getMessage())
          .isEqualTo(
              "Client certificate (hash=unknown) has 2 hostnames; truncating"
                  + " X-SSL-Certificate-Hostnames header to 1 hostnames (<= 5 bytes).");
    } finally {
      logger.removeHandler(logHandler);
    }
  }
}
