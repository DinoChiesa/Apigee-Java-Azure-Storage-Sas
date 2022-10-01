// Copyright 2019-2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callouts.azurestorage;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.callouts.CalloutBase;
import com.google.apigee.encoding.Base16;
import com.google.apigee.util.TimeResolver;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@IOIntensive
public class SasCallout extends CalloutBase implements Execution {
  private static final String varnamePrefix = "sas-";
  private static final String hmacAlgorithm = "HmacSHA256";

  protected static final String uriPatternString =
      "https://([^. ]+)\\.([^. ]+)\\.([^. ]+)\\.windows.net/([^/ ]+)(/([^ ]+))?$";
  protected static final Pattern uriPattern = Pattern.compile(uriPatternString);

  private static final Base64.Encoder base64Encoder = Base64.getEncoder();

  enum EncodingType {
    UTF8,
    BASE64,
    BASE64URL,
    BASE16,
    HEX
  };

  public SasCallout(Map properties) {
    super(properties);
  }

  public String getVarnamePrefix() {
    return varnamePrefix;
  }

  private String getPermissions(MessageContext msgCtxt) throws Exception {
    return (String) getSimpleRequiredProperty("permissions", msgCtxt);
  }

  private String getVersion(MessageContext msgCtxt) throws Exception {
    return (String) getSimpleOptionalProperty("version", msgCtxt);
  }

  private String getProtocol(MessageContext msgCtxt) throws Exception {
    return (String) getSimpleOptionalProperty("protocol", msgCtxt);
  }

  private String getIp(MessageContext msgCtxt) throws Exception {
    return (String) getSimpleOptionalProperty("ip", msgCtxt);
  }
  private String getIdentifier(MessageContext msgCtxt) throws Exception {
    return (String) getSimpleOptionalProperty("identifier", msgCtxt);
  }

  private int getTimeExpression(String variant, MessageContext msgCtxt) throws Exception {
    String timeExpressionString = (String) getSimpleOptionalProperty(variant, msgCtxt);
    Long durationInMilliseconds = 0L;
    if (timeExpressionString == null || timeExpressionString.trim().equals("")) {
      if (variant.equals("expiry")) {
        throw new IllegalStateException("missing expiry");
      } else if (!variant.equals("start")) {
        throw new IllegalStateException("unsupported timespan variant");
      }
    } else {
      durationInMilliseconds = TimeResolver.resolveExpression(timeExpressionString);
    }
    int durationInSeconds = ((Long) (durationInMilliseconds / 1000L)).intValue();
    Instant referenceTime = Instant.now();
    Instant instant = referenceTime.plus(durationInSeconds, ChronoUnit.SECONDS);
    int epochSecond = (int) instant.getEpochSecond();
    msgCtxt.setVariable(varName(variant + "-epoch-second"), Integer.toString(epochSecond));
    return epochSecond;
  }

  /* seconds since epoch of expiry */
  private int getExpiry(MessageContext msgCtxt) throws Exception {
    return getTimeExpression("expiry", msgCtxt);
  }

  /* seconds since epoch of start */
  private int getStart(MessageContext msgCtxt) throws Exception {
    return getTimeExpression("start", msgCtxt);
  }

  private String getResourceUri(MessageContext msgCtxt) throws Exception {
    return (String) getSimpleRequiredProperty("resource-uri", msgCtxt);
  }

  private String getResourceType(MessageContext msgCtxt) throws Exception {
    return (String) getSimpleOptionalProperty("resource-type", msgCtxt);
  }

  // ====================================================================

  private String encodeURIComponent(String s) {
    try {
      return URLEncoder.encode(s, "UTF-8").replaceAll("\\+", "%20");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  private byte[] getKey(MessageContext msgCtxt) throws Exception {
    byte[] keybytes = getByteArrayProperty(msgCtxt, "key");
    if (keybytes == null) throw new IllegalStateException("key resolves to null or empty.");

    return keybytes;
  }

  private byte[] decodeString(String s, EncodingType decodingKind) throws Exception {
    if (decodingKind == EncodingType.HEX || decodingKind == EncodingType.BASE16) {
      return Base16.decode(s);
    }
    if (decodingKind == EncodingType.BASE64) {
      return Base64.getDecoder().decode(s);
    }
    if (decodingKind == EncodingType.BASE64URL) {
      return Base64.getUrlDecoder().decode(s);
    }
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private String getStringProp(MessageContext msgCtxt, String name, String defaultValue)
      throws Exception {
    String value = this.properties.get(name);
    if (value != null) value = value.trim();
    if (value == null || value.equals("")) {
      return defaultValue;
    }
    value = resolveVariableReferences(value, msgCtxt);
    if (value == null || value.equals("")) {
      throw new IllegalStateException(name + " resolves to null or empty.");
    }
    return value;
  }

  private EncodingType getEncodingTypeProperty(MessageContext msgCtxt, String propName)
      throws Exception {
    return EncodingType.valueOf(getStringProp(msgCtxt, propName, "UTF8").toUpperCase());
  }

  private byte[] getByteArrayProperty(MessageContext msgCtxt, String propName) throws Exception {
    String thing = this.properties.get(propName);
    if (thing != null) thing = thing.trim();
    if (thing == null || thing.equals("")) {
      return null;
    }
    thing = resolveVariableReferences(thing, msgCtxt);
    if (thing == null || thing.equals("")) {
      throw new IllegalStateException(propName + " resolves to null or empty.");
    }
    EncodingType decodingKind = getEncodingTypeProperty(msgCtxt, propName + "-encoding");
    byte[] a = decodeString(thing, decodingKind);
    return a;
  }

  protected int getVersionYear(String version) {
    String[] parts = version.split("-");
    if (parts.length < 3) return 0;
    try {
      return Integer.parseInt(parts[0]);
    } catch (Exception e) {
      return 0;
    }
  }

  protected String getStringToSign(SasConfiguration config, MessageContext msgCtxt) throws Exception {
    /*
     * per https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas
     *
     * When constructing a SAS for Azure Blob service, the string to sign is like this:
     * version  2020-12-06
     * StringToSign = signedPermissions + "\n" +
     *                signedStart + "\n" +
     *                signedExpiry + "\n" +
     *                canonicalizedResource + "\n" +
     *                signedIdentifier + "\n" +
     *                signedIP + "\n" +
     *                signedProtocol + "\n" +
     *                signedVersion + "\n" +
     *                signedResource + "\n" +
     *                signedSnapshotTime + "\n" +
     *                signedEncryptionScope + "\n" +
     *                rscc + "\n" +
     *                rscd + "\n" +
     *                rsce + "\n" +
     *                rscl + "\n" +
     *                rsct
     *
     * version  2018-11-09
     *   everything in the 2020-12-06 form except signedEncryptionScope
     *
     * version  2015-04-05
     *   everything in the 2018-11-09 form except signedResource & signedSnapshotTime
     *
     * StringToSign = signedPermissions + "\n" +
     *                signedStart + "\n" +
     *                signedExpiry + "\n" +
     *                canonicalizedResource + "\n" +
     *                signedIdentifier + "\n" +
     *                signedIP + "\n" +
     *                signedProtocol + "\n" +
     *                signedVersion + "\n" +
     *                rscc + "\n" +
     *                rscd + "\n" +
     *                rsce + "\n" +
     *                rscl + "\n" +
     *                rsct
     *
     * When constructing the string to be signed:
     *
     * - If a field is optional and not provided as part of the request, specify
     *   an empty string for that field. Be sure to include the newline
     *   character (\n) after the empty string.
     *
     **/

    // I read in the source for the Java SDK that if identifier is specified,
    // then the permission and expiry should not be specified, because those
    // things are governed by the stored access policy.  (Maybe also the start
    // time?)  But I did not see that restriction in the documentation of the
    // REST API.  Maybe the identifier overrides what is specified in those
    // parameters.

    int versionYear = getVersionYear(config.version);
    if (versionYear < 2015 || versionYear > 2021) {
      // The versions are listed here:
      // https://learn.microsoft.com/en-us/rest/api/storageservices/previous-azure-storage-service-versions
      throw new IllegalStateException("unsupported SAS version year");
    }

    String c11dResource = canonicalizedResource(config.resourceUri);

    msgCtxt.setVariable(varName("canonicalized-resource"), c11dResource);

    List<String> parts = new ArrayList<String>();
    parts.add(config.permissions);
    parts.add(config.startString);
    parts.add(config.expiryString);
    parts.add(c11dResource);
    parts.add(config.identifier);
    parts.add(config.ip);
    parts.add(config.protocol);
    parts.add(config.version);

    // I could not find definitive documentation on the different SAS
    // formats. 2018 adds two params and 2020 adds encryptionScope.

    if (versionYear >= 2018) {
      parts.add(config.resourceType);
      parts.add(""); // snapshot time, an ISO8601 string
    }
    if (versionYear >= 2020) {
      parts.add(""); // encryption scope
    }

    parts.add(config.rscc);
    parts.add(config.rscd);
    parts.add(config.rsce);
    parts.add(config.rscl);
    parts.add(config.rsct);

    String stringToSign =
        parts.stream().collect(Collectors.joining("\n"));

    return stringToSign;
  }

  String getSasUri(SasConfiguration config, String signature) {
    // example URI:
    // https://myaccount.blob.core.windows.net/container/blob.ext?
    //   sv=2019-02-02&
    //   st=2019-04-29T22%3A18%3A26Z&
    //   se=2019-04-30T02%3A23%3A26Z&
    //   sr=b&
    //   sp=rw&
    //   sip=168.1.5.60-168.1.5.70&
    //   spr=https&
    //   sig=Z%2FRHIX5Xcg0Mq2rqI3OlWTjEg2tYkboXr1P9ZUXDtkk%3D

    Map<String, String> q = new LinkedHashMap<String, String>();
    q.put("sv", config.version);
    q.put("st", config.startString);
    q.put("se", config.expiryString);
    int versionYear = getVersionYear(config.version);
    if (versionYear >= 2018) {
      q.put("sr", config.resourceType);
    }
    q.put("sp", config.permissions);
    q.put("sip", config.ip);
    q.put("spr", config.protocol);
    q.put("sig", signature);
    String queryString =
        q.entrySet().stream()
            .filter(e -> e.getValue() != null && !e.getValue().equals(""))
            .map(e -> e.getKey() + "=" + encodeURIComponent(e.getValue()))
            .collect(Collectors.joining("&"));

    return String.format("%s?%s", config.resourceUri, queryString);
  }

  String canonicalizedResource(String uri) throws Exception {
    // https://myaccount.blob.core.windows.net/music/intro.mp3
    Matcher matcher = uriPattern.matcher(uri);
    if (!matcher.matches()) {
      throw new IllegalStateException("non-compliant URI");
    }

    // matcher.group(1) = account
    // matcher.group(2) = service
    // matcher.group(3) = "core" (always?)
    // matcher.group(4) = container
    // matcher.group(5) = (optional) object-with-leading-by-slash
    // matcher.group(6) = (optional) object

    if ((matcher.group(5) == null)) {
      return String.format("/%s/%s/%s", matcher.group(2), matcher.group(1), matcher.group(4));
    }
    return String.format(
        "/%s/%s/%s/%s", matcher.group(2), matcher.group(1), matcher.group(4), matcher.group(6));
  }

  static class SasConfiguration {
    public int startEpochSecond;
    public int expiryEpochSecond;
    public String permissions;
    public String version;
    public String protocol;
    public String resourceUri;
    public String resourceType;
    public String identifier;
    public String ip;
    public String startString;
    public String expiryString;
    public String rscc, rscd, rsce, rscl, rsct;

    public SasConfiguration() {
      version = "2018-11-09"; // 2015-04-05  // 2020-12-06
      protocol = "https";
      identifier = "";
      resourceType = "";
      ip = "";
      rscc = "";
      rscd = "";
      rsce = "";
      rscl = "";
      rsct = "";
    }

    public SasConfiguration withVersion(String version) {
      // one of the supported versions
      if (version != null && !version.trim().equals("")) {
        this.version = version;
      }
      return this;
    }

    public SasConfiguration withProtocol(String protocol) {
      // either http,https or https
      if (protocol != null && !protocol.trim().equals("")) {
        this.protocol = protocol;
      }
      return this;
    }

    public SasConfiguration withIp(String ip) {
      // either http,https or https
      if (ip != null && !ip.trim().equals("")) {
        this.ip = ip;
      }
      return this;
    }

    public SasConfiguration withIdentifier(String identifier) {
      // either http,https or https
      if (identifier != null && !identifier.trim().equals("")) {
        this.identifier = identifier;
      }
      return this;
    }

    public SasConfiguration withPermissions(String permissions) {
      // subset of racwdxltmeop in that order,.
      // different services suppoer different subsets of permissions. Eg
      // Blob       racwd
      // Container  racwdl
      this.permissions = permissions;
      return this;
    }

    public SasConfiguration withStart(int start) {
      this.startEpochSecond = start;
      this.startString = Instant.ofEpochSecond(this.startEpochSecond).toString();
      return this;
    }

    public SasConfiguration withExpiry(int expiry) {
      this.expiryEpochSecond = expiry;
      this.expiryString = Instant.ofEpochSecond(this.expiryEpochSecond).toString();
      return this;
    }

    public SasConfiguration withResourceUri(String uri) {
      this.resourceUri = uri;
      return this;
    }

    public SasConfiguration withResourceType(String typ) {
      if (typ != null && !typ.trim().equals("")) {
        this.resourceType = typ;
      }
      return this;
    }
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    try {
      boolean debug = getDebug();
      SasConfiguration sasConfiguration =
          new SasConfiguration()
              .withVersion(getVersion(msgCtxt))
              .withPermissions(getPermissions(msgCtxt))
              .withStart(getStart(msgCtxt))
              .withExpiry(getExpiry(msgCtxt))
              .withProtocol(getProtocol(msgCtxt))
              .withResourceUri(getResourceUri(msgCtxt))
              .withResourceType(getResourceType(msgCtxt))
              .withIp(getIp(msgCtxt))
              .withIdentifier(getIdentifier(msgCtxt));

      clearVariables(msgCtxt);
      msgCtxt.removeVariable(varName("params"));
      byte[] keyBytes = getKey(msgCtxt);
      if (debug) {
        msgCtxt.setVariable(varName("key-b16"), Base16.encode(keyBytes));
        msgCtxt.setVariable(varName("key-b64"), base64Encoder.encodeToString(keyBytes));
      }

      Mac hmac = Mac.getInstance(hmacAlgorithm);
      hmac.init(new SecretKeySpec(keyBytes, hmacAlgorithm));
      String stringToSign = getStringToSign(sasConfiguration, msgCtxt);
      msgCtxt.setVariable(varName("string-to-sign"), stringToSign);
      byte[] hmacBytes = hmac.doFinal(stringToSign.getBytes("UTF-8"));
      String hmacB64 = new String(base64Encoder.encode(hmacBytes), "UTF-8");
      msgCtxt.setVariable(varName("sig"), hmacB64);
      String sasUri = getSasUri(sasConfiguration, hmacB64);
      msgCtxt.setVariable(varName("uri"), sasUri);
    } catch (Exception e) {
      msgCtxt.setVariable(varName("error"), e.getMessage());
      msgCtxt.setVariable(varName("stacktrace"), getStackTraceAsString(e));
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
