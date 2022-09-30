# Azure Storage SAS Token Callout

This directory contains Java source code for a callout which produces a
SAS token for Azure Blob service.  Also it includes a working sample proxy.

## Background

"SAS" refers to [Shared Access
Signature](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview),
This is Microsoft's convention for applying [HMAC](https://en.wikipedia.org/wiki/HMAC), in
other words a keyed-hash message authentication code, to produce a cryptographic
signature for authentication purposes.

HMAC is easy to compute in Apigee with the builtin features, like the HMAC
policy and the hmac static function. But, the structure of Microsoft's token is
not a simple HMAC. Instead it is a series of parameters (sr, se, skn, sig)
encoded according to the `x-www-form-urlencoded` standard. An Storage URL with
the SAS signature applied follows this structure for Blob storage:

```
https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER/OBJECT?BLOB_SAS
```
...where the BLOB_SAS itself might look like this:
```
sv=2019-02-02&st=2019-04-29T22%3A18%3A26Z&se=2019-04-30T02%3A23%3A26Z&sr=b&sp=rw&sip=168.1.5.60-168.1.5.70&spr=https&sig=Z%2FRHIX5Xcg0Mq2rqI3OlWTjEg2tYkboXr1P9ZUXDtkk%3D

```

While producing an HMAC is _relatively straightforward_ in Apigee just using the
builtin hmac capabilities and AssignMessage, assembling and encoding all of the
pieces required by Microsoft for a SAS token can be sort of tedious. Therefore,
I built this callout to aid in the assembly.

The core of the Java logic is:
```
  Mac hmac = Mac.getInstance("HmacSHA256");
  hmac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
  String stringToSign = getStringToSign(...);
  byte[] hmacBytes = hmac.doFinal(stringToSign.getBytes("UTF-8"));
  String hmacB64 = new String(base64Encoder.encode(hmacBytes), "UTF-8");

  String sasUri =
      String.format(
          "https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER/OBJECT?BLOB_SAS",
          accountName,
          container,
          object,
          blobSas);
```

The rest of the callout code is built for getting and validating input, and setting output.

## What's here?

The points of interest here in this repository:

- [Java source](./callout) - Java code, as well as instructions for how to build the Java code.
- [example proxy](./example-bundle) - an example API Proxy for Apigee Edge that shows how to use the resulting Java callout.

The API Proxy subdirectory here includes the pre-built JAR file. There are no
other dependencies. Therefore you do not need to build the Java code in order to
use this callout. However, you may wish to modify this code for your own
purposes. In that case, you will modify the Java code, re-build, then copy that
JAR into the appropriate `apiproxy/resources/java` directory for the API Proxy.

## Usage

Deploy the proxy bundle, and the invoke it like this:
```
# Edge
endpoint=https://${ORG}-${ENV}.apigee.net
# X or hybrid
endpoint=https://my-api-endpoint.net

curl -i $endpoint/azure-storage-sas/sig -X POST -d ''

```

## Policy Configuration

Here's an example policy configuration:

```
<JavaCallout name='Java-GenerateSas-1'>
  <Properties>
    <Property name="version">2015-04-05</Property>
    <Property name="key">{private.shared_access_key}</Property>
    <Property name="key-encoding">base64</Property>
    <Property name="permissions">r</Property>
    <Property name="resource-uri">https://myaccount.blob.core.windows.net/container/blob.txt</Property>
    <Property name="expiry">1h</Property>
    <Property name="ip">172.134.12.11</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.azurestorage.SasCallout</ClassName>
  <ResourceURL>java://apigee-azure-storage-sas-callout-20220930.jar</ResourceURL>
</JavaCallout>
```

The key is the "shared access key" provided by Azure, and typically looks something like this:
`B1OrZzY26crAJcxXpyEIaqbs7qNLGWXuR9mDL4U7mC4=`

The output is emitted into context variables:
* `sas-sig` - the signature in base64-encoded format
* `sas-uri` - the complete URI

You can then use the generated URI to connect directly to the blob service. Take
care sharing the URL: it is a key.


## Policy Properties

| property name    | description                                                                                                                              |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `version`        | optional. The version of the Azure signature standard. Default: "2015-04-05"                                                             |
| `key`            | required. The string representing the shared key.                                                                                        |
| `key-encoding`   | optional. One of: {`hex`, `base16`, `base64`, `utf8`}. This affects how the policy decodes the key from the key string. base16 is an alias for hex. The default is "utf8". |
| `resource-uri`   | required. The URI to sign. This URI should include the scheme (https). It seems to work without it. |
| `resource-type`  | optional. The resource type. For the Blob swervice, "b" means a blob. Consult the Azure documentation for more information. |
| `expiry`         | required. The expiry, expressed as a relative time. An integer followed by a letter {s,m,h,d}: 7d = 7 days. 5h = 5 hours.       |
| `start`          | optional. The start interval, expressed as a relative time.  |
| `protocol`       | optional. One of "https" or "http,https". Defaults to https.   |
| `permissions`    | required. A permission string like "r" or "rw". Consult the Azure documentation for options for various services.   |
| `ip`             | optional. An IP address or an IP address range expressed as, for example 12.20.36.42-12.20.36.81.   |
| `identifier`     | optional. An identifier for the SAS access control policy.   |



## Building

You don't need to build the code to use it. If you like you can rebuild with
this command:

```
mvn clean package
```


## License

This code is Copyright (c) 2019-2022 Google LLC, and is released under the Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Bugs

* I don't have an Azure Blob account and Azure does not publish test vectors, so I cannot test this against known good signatures. 
