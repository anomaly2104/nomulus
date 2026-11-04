// Copyright 2023 The Nomulus Authors. All Rights Reserved.
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

package google.registry.ui.server.console.settings;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static google.registry.persistence.transaction.TransactionManagerFactory.tm;
import static google.registry.request.Action.Method.POST;
import static google.registry.util.X509Utils.getCertificateHash;
import static google.registry.util.X509Utils.loadCertificate;
import static jakarta.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Streams;
import google.registry.flows.certs.CertificateChecker;
import google.registry.flows.certs.CertificateChecker.InsecureCertificateException;
import google.registry.model.console.ConsolePermission;
import google.registry.model.console.ConsoleUpdateHistory;
import google.registry.model.console.User;
import google.registry.model.registrar.Registrar;
import google.registry.request.Action;
import google.registry.request.Action.Service;
import google.registry.request.Parameter;
import google.registry.request.auth.Auth;
import google.registry.request.auth.AuthenticatedRegistrarAccessor;
import google.registry.request.auth.AuthenticatedRegistrarAccessor.RegistrarAccessDeniedException;
import google.registry.ui.server.console.ConsoleApiAction;
import google.registry.ui.server.console.ConsoleApiParams;
import jakarta.inject.Inject;
import java.security.cert.CertificateParsingException;
import java.time.Instant;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.function.BiConsumer;

@Action(
    service = Service.CONSOLE,
    path = SecurityAction.PATH,
    method = {POST},
    auth = Auth.AUTH_PUBLIC_LOGGED_IN)
public class SecurityAction extends ConsoleApiAction {

  static final String PATH = "/console-api/settings/security";
  private static final String PEM_HEADER = "-----BEGIN CERTIFICATE-----";
  private final String registrarId;
  private final AuthenticatedRegistrarAccessor registrarAccessor;
  private final Optional<Registrar> registrar;
  private final CertificateChecker certificateChecker;

  @Inject
  public SecurityAction(
      ConsoleApiParams consoleApiParams,
      CertificateChecker certificateChecker,
      AuthenticatedRegistrarAccessor registrarAccessor,
      @Parameter("registrarId") String registrarId,
      @Parameter("registrar") Optional<Registrar> registrar) {
    super(consoleApiParams);
    this.registrarId = registrarId;
    this.registrarAccessor = registrarAccessor;
    this.registrar = registrar;
    this.certificateChecker = certificateChecker;
  }

  @Override
  protected void postHandler(User user) {
    checkPermission(user, registrarId, ConsolePermission.EDIT_REGISTRAR_DETAILS);
    checkArgument(registrar.isPresent(), "'registrar' parameter is not present");

    Registrar savedRegistrar;
    try {
      savedRegistrar = registrarAccessor.getRegistrar(registrarId);
    } catch (RegistrarAccessDeniedException e) {
      setFailedResponse(e.getMessage(), SC_FORBIDDEN);
      return;
    }

    tm().transact(() -> setResponse(savedRegistrar));
  }

  private void setResponse(Registrar savedRegistrar) {
    Registrar registrarParameter = registrar.get();
    Registrar.Builder updatedRegistrarBuilder = savedRegistrar.asBuilder();
    StringJoiner updates = new StringJoiner(",");

    if (!savedRegistrar
        .getIpAddressAllowList()
        .equals(registrarParameter.getIpAddressAllowList())) {
      updatedRegistrarBuilder.setIpAddressAllowList(registrarParameter.getIpAddressAllowList());
      updates.add("IP_CHANGE");
    }

    // Once a registrar has moved to hostname-based certificate authorization, the console does not
    // let it fall back to having no hostnames; it can only replace them.
    boolean hostnamesConfigured =
        !registrarParameter.getAllowedEppClientCertificateHostnames().isEmpty();
    checkArgument(
        hostnamesConfigured || savedRegistrar.getAllowedEppClientCertificateHostnames().isEmpty(),
        "At least one EPP client certificate hostname must remain configured");

    try {
      // The builder canonicalizes and validates both lists, naming the offending entry on failure.
      updatedRegistrarBuilder
          .setAllowedEppClientCertificateHostnames(
              registrarParameter.getAllowedEppClientCertificateHostnames())
          .setRevokedClientCertificateHashes(
              toCertificateHashes(registrarParameter.getRevokedClientCertificateHashes()));
      if (applyCertificateChange(
          savedRegistrar.getClientCertificate(),
          registrarParameter.getClientCertificate(),
          hostnamesConfigured,
          updatedRegistrarBuilder::setClientCertificate)) {
        updates.add("PRIMARY_SSL_CERT_CHANGE");
      }
      if (applyCertificateChange(
          savedRegistrar.getFailoverClientCertificate(),
          registrarParameter.getFailoverClientCertificate(),
          hostnamesConfigured,
          updatedRegistrarBuilder::setFailoverClientCertificate)) {
        updates.add("FAILOVER_SSL_CERT_CHANGE");
      }
    } catch (InsecureCertificateException | IllegalArgumentException e) {
      setFailedResponse(e.getMessage(), SC_BAD_REQUEST);
      return;
    }

    Registrar updatedRegistrar = updatedRegistrarBuilder.build();
    if (!savedRegistrar
        .getAllowedEppClientCertificateHostnames()
        .equals(updatedRegistrar.getAllowedEppClientCertificateHostnames())) {
      updates.add("EPP_CERT_HOSTNAMES_CHANGE");
    }
    if (!savedRegistrar
        .getRevokedClientCertificateHashes()
        .equals(updatedRegistrar.getRevokedClientCertificateHashes())) {
      updates.add("REVOKED_CERTS_CHANGE");
    }
    tm().put(updatedRegistrar);
    finishAndPersistConsoleUpdateHistory(
        new ConsoleUpdateHistory.Builder()
            .setType(ConsoleUpdateHistory.Type.REGISTRAR_SECURITY_UPDATE)
            .setDescription(
                String.format(
                    "%s%s%s", registrarId, ConsoleUpdateHistory.DESCRIPTION_SEPARATOR, updates)));

    sendExternalUpdatesIfNecessary(
        EmailInfo.create(savedRegistrar, updatedRegistrar, ImmutableSet.of(), ImmutableSet.of()));
    consoleApiParams.response().setStatus(SC_OK);
  }

  /**
   * Applies a requested change to a stored certificate and returns whether anything changed.
   *
   * <p>An absent value leaves the stored certificate as it is. An empty string removes it, which is
   * only allowed while at least one hostname is configured so that the registrar always keeps a way
   * to log in. Any other value is validated and stored as the new certificate.
   */
  private boolean applyCertificateChange(
      Optional<String> savedCertificate,
      Optional<String> requestedCertificate,
      boolean hostnamesConfigured,
      BiConsumer<String, Instant> setter)
      throws InsecureCertificateException {
    if (requestedCertificate.isEmpty() || requestedCertificate.equals(savedCertificate)) {
      return false;
    }
    String newCertificate = requestedCertificate.get();
    if (newCertificate.isEmpty()) {
      if (savedCertificate.isEmpty()) {
        return false;
      }
      checkArgument(
          hostnamesConfigured,
          "A client certificate can only be removed once at least one EPP client certificate"
              + " hostname is configured");
    } else {
      certificateChecker.validateCertificate(newCertificate);
    }
    setter.accept(newCertificate, tm().getTxTime());
    return true;
  }

  /**
   * Converts the revoked certificate list from the console into certificate hashes.
   *
   * <p>Existing entries round-trip as hashes; a newly revoked certificate is pasted as a PEM and is
   * stored as its hash, matching what the EPP server computes for a presented certificate.
   */
  private static ImmutableList<String> toCertificateHashes(Iterable<String> hashesOrPems) {
    return Streams.stream(hashesOrPems)
        .map(SecurityAction::toCertificateHash)
        .collect(toImmutableList());
  }

  private static String toCertificateHash(String hashOrPem) {
    if (!hashOrPem.contains(PEM_HEADER)) {
      return hashOrPem;
    }
    try {
      return getCertificateHash(loadCertificate(hashOrPem));
    } catch (CertificateParsingException e) {
      throw new IllegalArgumentException(
          "Could not parse revoked certificate: " + e.getMessage(), e);
    }
  }
}
