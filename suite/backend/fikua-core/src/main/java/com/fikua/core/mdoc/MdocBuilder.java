package com.fikua.core.mdoc;

import com.fikua.core.crypto.SigningKey;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.upokecenter.cbor.CBORObject;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Builds mso_mdoc credentials per ISO 18013-5.
 * Creates the Document CBOR structure with IssuerSignedItems, MSO, and COSE_Sign1 issuerAuth.
 *
 * Usage mirrors SdJwtBuilder:
 * <pre>
 *   new MdocBuilder(issuerKey)
 *       .docType("eu.europa.ec.eudi.pid.1")
 *       .namespace("eu.europa.ec.eudi.pid.1")
 *       .element("given_name", "Jan")
 *       .element("family_name", "Kowalski")
 *       .deviceKey(walletEcKey)
 *       .x5cChain(issuerKey.x5cChain())
 *       .build();
 * </pre>
 */
public class MdocBuilder {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SigningKey issuerKey;
    private String docType;
    private String currentNamespace;
    private final Map<String, List<ElementEntry>> namespaceElements = new LinkedHashMap<>();
    private ECKey deviceKey;
    private List<Base64> x5cChain;
    private long validityDays = 365;

    public MdocBuilder(SigningKey issuerKey) {
        this.issuerKey = issuerKey;
    }

    public MdocBuilder docType(String docType) {
        this.docType = docType;
        return this;
    }

    /** Set the current namespace. Subsequent element() calls add to this namespace. */
    public MdocBuilder namespace(String namespace) {
        this.currentNamespace = namespace;
        this.namespaceElements.putIfAbsent(namespace, new ArrayList<>());
        return this;
    }

    /** Add an element to the current namespace. */
    public MdocBuilder element(String identifier, Object value) {
        if (currentNamespace == null) {
            throw new IllegalStateException("Call namespace() before element()");
        }
        namespaceElements.get(currentNamespace).add(new ElementEntry(identifier, value));
        return this;
    }

    /** Set the device/wallet public key (for deviceKeyInfo in MSO). */
    public MdocBuilder deviceKey(ECKey deviceKey) {
        this.deviceKey = deviceKey;
        return this;
    }

    /** Set x5c certificate chain for COSE unprotected header. */
    public MdocBuilder x5cChain(List<Base64> x5cChain) {
        this.x5cChain = x5cChain;
        return this;
    }

    public MdocBuilder validityDays(long days) {
        this.validityDays = days;
        return this;
    }

    /** Build the mso_mdoc Document. */
    public MdocDocument build() {
        if (docType == null || docType.isBlank()) {
            throw new IllegalStateException("docType is required for mso_mdoc");
        }
        if (namespaceElements.isEmpty()) {
            throw new IllegalStateException("At least one namespace with elements is required");
        }

        // 1. Build IssuerSignedItems per namespace and compute digests
        Map<String, CBORObject> nameSpacesCbor = new LinkedHashMap<>();
        Map<String, Map<Integer, byte[]>> valueDigests = new LinkedHashMap<>();

        for (var nsEntry : namespaceElements.entrySet()) {
            String ns = nsEntry.getKey();
            List<ElementEntry> elements = nsEntry.getValue();
            CBORObject itemsArray = CBORObject.NewArray();
            Map<Integer, byte[]> nsDigests = new LinkedHashMap<>();

            for (int i = 0; i < elements.size(); i++) {
                ElementEntry elem = elements.get(i);
                byte[] itemBytes = buildIssuerSignedItem(i, elem);

                // Wrap in tag 24 (encoded-cbor) per ISO 18013-5 §8.3.2.1.2.2
                CBORObject taggedItem = CBORObject.FromObject(itemBytes).WithTag(24);
                itemsArray.Add(taggedItem);

                // Digest of the *tagged* IssuerSignedItemBytes (#6.24(...)) per
                // ISO 18013-5 §9.1.2.5 — the full encoding stored in nameSpaces,
                // not the inner untagged bytes.
                nsDigests.put(i, sha256(taggedItem.EncodeToBytes()));
            }

            nameSpacesCbor.put(ns, itemsArray);
            valueDigests.put(ns, nsDigests);
        }

        // 2. Build MobileSecurityObject (MSO)
        byte[] msoBytes = buildMso(valueDigests);

        // 3. Wrap MSO in tag 24 (MobileSecurityObjectBytes = #6.24(bstr .cbor MSO))
        //    per ISO 18013-5, the COSE_Sign1 payload is the tagged MSO, not raw bytes
        CBORObject taggedMso = CBORObject.FromObject(msoBytes).WithTag(24);
        byte[] msoPayload = taggedMso.EncodeToBytes();

        // 4. Sign with COSE_Sign1 (issuerAuth)
        List<byte[]> x5cDer = convertX5cToDer();
        byte[] issuerAuth = CoseSign1.sign(msoPayload, issuerKey, x5cDer);

        // 4. Assemble IssuerSigned CBOR (per OID4VCI A.2.4)
        CBORObject issuerSigned = CBORObject.NewMap();
        issuerSigned.set(CBORObject.FromObject("issuerAuth"),
                CBORObject.DecodeFromBytes(issuerAuth));
        CBORObject nameSpacesMap = CBORObject.NewMap();
        for (var entry : nameSpacesCbor.entrySet()) {
            nameSpacesMap.set(CBORObject.FromObject(entry.getKey()), entry.getValue());
        }
        issuerSigned.set(CBORObject.FromObject("nameSpaces"), nameSpacesMap);

        return new MdocDocument(issuerSigned.EncodeToBytes());
    }

    // --- Private helpers ---

    private byte[] buildIssuerSignedItem(int digestId, ElementEntry elem) {
        CBORObject item = CBORObject.NewMap();
        item.set(CBORObject.FromObject("digestID"), CBORObject.FromObject(digestId));

        byte[] randomBytes = new byte[16];
        RANDOM.nextBytes(randomBytes);
        item.set(CBORObject.FromObject("random"), CBORObject.FromObject(randomBytes));

        item.set(CBORObject.FromObject("elementIdentifier"),
                CBORObject.FromObject(elem.identifier()));
        item.set(CBORObject.FromObject("elementValue"), toCbor(elem.value()));

        return item.EncodeToBytes();
    }

    private byte[] buildMso(Map<String, Map<Integer, byte[]>> valueDigests) {
        CBORObject mso = CBORObject.NewMap();
        mso.set(CBORObject.FromObject("version"), CBORObject.FromObject("1.0"));
        mso.set(CBORObject.FromObject("digestAlgorithm"), CBORObject.FromObject("SHA-256"));

        // valueDigests: { namespace: { digestID: digest_bytes, ... } }
        CBORObject vdMap = CBORObject.NewMap();
        for (var nsEntry : valueDigests.entrySet()) {
            CBORObject digestMap = CBORObject.NewMap();
            for (var dEntry : nsEntry.getValue().entrySet()) {
                digestMap.set(CBORObject.FromObject(dEntry.getKey()),
                        CBORObject.FromObject(dEntry.getValue()));
            }
            vdMap.set(CBORObject.FromObject(nsEntry.getKey()), digestMap);
        }
        mso.set(CBORObject.FromObject("valueDigests"), vdMap);

        // deviceKeyInfo (wallet public key as COSE_Key)
        if (deviceKey != null) {
            CBORObject deviceKeyInfo = CBORObject.NewMap();
            deviceKeyInfo.set(CBORObject.FromObject("deviceKey"), ecKeyToCoseKey(deviceKey));
            mso.set(CBORObject.FromObject("deviceKeyInfo"), deviceKeyInfo);
        }

        mso.set(CBORObject.FromObject("docType"), CBORObject.FromObject(docType));

        // validityInfo
        Instant now = Instant.now();
        CBORObject validity = CBORObject.NewMap();
        validity.set(CBORObject.FromObject("signed"), cborDatetime(now));
        validity.set(CBORObject.FromObject("validFrom"), cborDatetime(now));
        validity.set(CBORObject.FromObject("validUntil"),
                cborDatetime(now.plusSeconds(validityDays * 86400)));
        mso.set(CBORObject.FromObject("validityInfo"), validity);

        return mso.EncodeToBytes();
    }

    /** Convert an EC JWK to COSE_Key format (CBOR map with integer labels). */
    private static CBORObject ecKeyToCoseKey(ECKey ecKey) {
        CBORObject key = CBORObject.NewMap();
        key.set(CBORObject.FromObject(1), CBORObject.FromObject(2));   // kty: EC2
        key.set(CBORObject.FromObject(-1), CBORObject.FromObject(1));  // crv: P-256
        key.set(CBORObject.FromObject(-2),
                CBORObject.FromObject(ecKey.getX().decode()));          // x coordinate
        key.set(CBORObject.FromObject(-3),
                CBORObject.FromObject(ecKey.getY().decode()));          // y coordinate
        return key;
    }

    /** ISO 18013-5 tdate: CBOR tag 0 with ISO 8601 datetime string. */
    private static CBORObject cborDatetime(Instant instant) {
        String iso = DateTimeFormatter.ISO_INSTANT.format(instant);
        return CBORObject.FromObject(iso).WithTag(0);
    }

    private static CBORObject toCbor(Object value) {
        if (value instanceof String s) return CBORObject.FromObject(s);
        if (value instanceof Integer i) return CBORObject.FromObject(i);
        if (value instanceof Long l) return CBORObject.FromObject(l);
        if (value instanceof Boolean b) return CBORObject.FromObject(b);
        if (value instanceof byte[] bytes) return CBORObject.FromObject(bytes);
        return CBORObject.FromObject(value.toString());
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private List<byte[]> convertX5cToDer() {
        if (x5cChain == null || x5cChain.isEmpty()) return List.of();
        return x5cChain.stream()
                .map(Base64::decode)
                .toList();
    }

    private record ElementEntry(String identifier, Object value) {}
}
