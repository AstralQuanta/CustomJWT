package top.pulselink.customjwt;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.math.BigInteger;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class CustomJWT {

    private final Gson gson;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String EC_ALGORITHM = "ECDSA";

    private static final String HMAC_ALGORITHM_256 = "HmacSHA256";
    private static final String HMAC_ALGORITHM_384 = "HmacSHA384";
    private static final String HMAC_ALGORITHM_512 = "HmacSHA512";

    private static final String PS_SIGNATURE_ALGORITHM_SHA256 = "SHA256withRSAandMGF1";
    private static final String PS_SIGNATURE_ALGORITHM_SHA384 = "SHA384withRSAandMGF1";
    private static final String PS_SIGNATURE_ALGORITHM_SHA512 = "SHA512withRSAandMGF1";

    private static final String RS_SIGNATURE_ALGORITHM_SHA256 = "SHA256withRSA";
    private static final String RS_SIGNATURE_ALGORITHM_SHA384 = "SHA384withRSA";
    private static final String RS_SIGNATURE_ALGORITHM_SHA512 = "SHA512withRSA";

    private static final String ES_SIGNATURE_ALGORITHM_SHA256 = "SHA256withECDSA";
    private static final String ES_SIGNATURE_ALGORITHM_SHA384 = "SHA384withECDSA";
    private static final String ES_SIGNATURE_ALGORITHM_SHA512 = "SHA512withECDSA";

    private PublicKey rsaPublicKey;
    private PrivateKey rsaPrivateKey;
    private PublicKey ECpublicKey;
    private PrivateKey ECprivateKey;
    private String privateKeyPEM, publicKeyPEM;

    public CustomJWT() {
        this.gson = new Gson();
    }

    public CustomJWT(int alg) {
        this.gson = new Gson();
        if (alg > 0) {
            if (alg >= 1024) { // RSA1024 not recommanded
                KeyPair rsaKeyPair = generateRSAKeyPair(alg);
                this.rsaPublicKey = rsaKeyPair.getPublic();
                this.rsaPrivateKey = rsaKeyPair.getPrivate();

                this.publicKeyPEM = getPEM(null, rsaPublicKey);
                this.privateKeyPEM = getPEM(rsaPrivateKey, null);

            } else {
                KeyPair ecKeyPair = generateECKeyPair("secp" + alg + "r1");
                this.ECpublicKey = ecKeyPair.getPublic();
                this.ECprivateKey = ecKeyPair.getPrivate();

                this.publicKeyPEM = getPEM(null, ECpublicKey);
                this.privateKeyPEM = getPEM(ECprivateKey, null);

                //System.out.println(Base64.getEncoder().encodeToString(ECprivateKey.getEncoded()));
                //System.out.println(Base64.getEncoder().encodeToString(ECpublicKey.getEncoded()));
            }
        } else {
            throw new IllegalArgumentException("Failed to initialized");
        }
    }

    private KeyPair generateRSAKeyPair(int keySize) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Failed to generate RSA key pair", ex);
        }
    }

    private KeyPair generateECKeyPair(String curveName) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM);
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Failed to generate EC key pair", e);
        }
    }

    public String Header(String alg, String type, String... additionalParameters) {
        JsonObject header = new JsonObject();
        header.addProperty("alg", alg);
        header.addProperty("typ", type);
        for (int i = 0; i < additionalParameters.length; i += 2) {
            header.addProperty(additionalParameters[i], additionalParameters[i + 1]);
        }
        return encodeBase64Url(gson.toJson(header).getBytes());
    }

    public String Payload(boolean[] isNumOrBoolean, String... parameters) {
        if (parameters.length % 2 != 0 || (parameters.length / 2) != isNumOrBoolean.length) {
            throw new IllegalArgumentException("Invalid number of parameters");
        }

        JsonObject payloadMessage = new JsonObject();
        for (int i = 0; i < parameters.length; i += 2) {
            String paramName = parameters[i];
            String paramValue = parameters[i + 1];

            if (isNumOrBoolean[i / 2]) {
                if ("true".equals(paramValue.toLowerCase())) {
                    payloadMessage.addProperty(paramName, true);
                } else if ("false".equals(paramValue.toLowerCase())) {
                    payloadMessage.addProperty(paramName, false);
                } else {
                    long longValue = Long.parseLong(paramValue);
                    payloadMessage.addProperty(paramName, longValue);
                }
            } else {
                payloadMessage.addProperty(paramName, paramValue);
            }
        }
        return encodeBase64Url(gson.toJson(payloadMessage).getBytes());
    }

    public String Signature(String Algorithm, String data, String key) {
        try {
            return switch (Algorithm) {
                case "HS256" ->
                    HMACCrypto(HMAC_ALGORITHM_256, key, data);
                case "HS384" ->
                    HMACCrypto(HMAC_ALGORITHM_384, key, data);
                case "HS512" ->
                    HMACCrypto(HMAC_ALGORITHM_512, key, data);
                default ->
                    HMACCrypto(HMAC_ALGORITHM_256, key, data);
            };
        } catch (Exception ex) {
            return ex.getLocalizedMessage();
        }
    }

    public String Signature(String Algorithm, String data) {
        try {
            return switch (Algorithm) {
                case "PS256" ->
                    PSCrypto(PS_SIGNATURE_ALGORITHM_SHA256, data, rsaPrivateKey);
                case "PS384" ->
                    PSCrypto(PS_SIGNATURE_ALGORITHM_SHA384, data, rsaPrivateKey);
                case "PS512" ->
                    PSCrypto(PS_SIGNATURE_ALGORITHM_SHA512, data, rsaPrivateKey);
                case "RS256" ->
                    RSCrypto(RS_SIGNATURE_ALGORITHM_SHA256, data, rsaPrivateKey);
                case "RS384" ->
                    RSCrypto(RS_SIGNATURE_ALGORITHM_SHA384, data, rsaPrivateKey);
                case "RS512" ->
                    RSCrypto(RS_SIGNATURE_ALGORITHM_SHA512, data, rsaPrivateKey);
                case "ES256" ->
                    ESCrypto(ES_SIGNATURE_ALGORITHM_SHA256, data, ECprivateKey);
                case "ES384" ->
                    ESCrypto(ES_SIGNATURE_ALGORITHM_SHA384, data, ECprivateKey);
                case "ES512" ->
                    ESCrypto(ES_SIGNATURE_ALGORITHM_SHA512, data, ECprivateKey);
                default ->
                    ESCrypto(ES_SIGNATURE_ALGORITHM_SHA256, data, ECprivateKey);
            };
        } catch (Exception ex) {
            return ex.getLocalizedMessage();
        }
    }

    private String HMACCrypto(String algorithm, String key, String data) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return encodeBase64Url(hmacBytes);
        } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
            throw new RuntimeException("Failed to compute HMAC Algorithm", ex);
        }
    }

    public boolean verifyHS(String jwt, String algorithm, String key) {
        try {
            int firstDot = jwt.indexOf(".");
            int lastDot = jwt.lastIndexOf(".");

            if (firstDot < 0 || lastDot < 0 || firstDot == lastDot) {
                return false;
            }

            String headerBase64 = jwt.substring(0, firstDot);
            String payloadBase64 = jwt.substring(firstDot + 1, lastDot);
            String providedSignature = jwt.substring(lastDot + 1);

            String dataToVerify = headerBase64 + "." + payloadBase64;
            String expectedSignature = Signature(algorithm, dataToVerify, key);

            return providedSignature.equals(expectedSignature);
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    private String PSCrypto(String signatureAlgorithm, String data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return encodeBase64Url(signature.sign());
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex) {
            ex.printStackTrace();
            return ex.getMessage();
        }
    }

    public boolean verifyPS(String jwt, String signature, String signatureAlgorithm, PublicKey publicKey) {
        try {
            Signature verifySignature = Signature.getInstance(signatureAlgorithm);
            verifySignature.initVerify(publicKey);
            String data = jwt.substring(0, jwt.lastIndexOf("."));
            verifySignature.update(data.getBytes(StandardCharsets.UTF_8));
            return verifySignature.verify(decodeBase64Url(signature));
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    private String RSCrypto(String signatureAlgorithm, String data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return encodeBase64Url(signature.sign());
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex) {
            ex.printStackTrace();
            return ex.getMessage();
        }
    }

    public boolean verifyRS(String jwt, String signature, String signatureAlgorithm, PublicKey publicKey) {
        try {
            Signature verifySignature = Signature.getInstance(signatureAlgorithm);
            verifySignature.initVerify(publicKey);
            String data = jwt.substring(0, jwt.lastIndexOf("."));
            verifySignature.update(data.getBytes(StandardCharsets.UTF_8));
            return verifySignature.verify(decodeBase64Url(signature));
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    private String ESCrypto(String algo, String data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(algo);
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] derSignature = signature.sign();

            BigInteger[] rs = decodeDER(derSignature);

            byte[] rawSignature = encodeSignatureToRaw(rs[0], rs[1], getSignatureLength(algo) / 2);

            return encodeBase64Url(rawSignature);
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException("Failed to compute ECDSA signature", e);
        }
    }

    public boolean verifyES(String jwt, String signature, String algo, PublicKey publicKey) {
        try {
            Signature verifySignature = Signature.getInstance(algo);
            verifySignature.initVerify(publicKey);
            String data = jwt.substring(0, jwt.lastIndexOf("."));
            verifySignature.update(data.getBytes(StandardCharsets.UTF_8));

            byte[] rawSignatureBytes = decodeBase64Url(signature);

            byte[] derSignatureBytes = convertRawToDer(rawSignatureBytes, algo);

            return verifySignature.verify(derSignatureBytes);
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException("Failed to verify ECDSA signature", e);
        }
    }

    private byte[] encodeSignatureToRaw(BigInteger r, BigInteger s, int componentLength) {
        byte[] rawSignature = new byte[2 * componentLength];
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        System.arraycopy(rBytes, Math.max(0, rBytes.length - componentLength), rawSignature,
                Math.max(0, componentLength - rBytes.length), Math.min(componentLength, rBytes.length));
        System.arraycopy(sBytes, Math.max(0, sBytes.length - componentLength), rawSignature,
                componentLength + Math.max(0, componentLength - sBytes.length), Math.min(componentLength, sBytes.length));

        return rawSignature;
    }

    private BigInteger[] decodeDER(byte[] derSignature) throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(derSignature);
        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

        return new BigInteger[]{r, s};
    }

    private byte[] convertRawToDer(byte[] rawSignature, String algo) throws IOException {
        int componentSize = getSignatureLength(algo) / 2;

        if (rawSignature.length != 2 * componentSize) {
            throw new IllegalArgumentException("The size of the raw signature is incorrect for the algorithm: " + algo);
        }

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rawSignature, 0, componentSize));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rawSignature, componentSize, 2 * componentSize));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        DERSequence seq = new DERSequence(v);

        return seq.getEncoded("DER");
    }

    private int getSignatureLength(String algo) {
        switch (algo) {
            case "SHA256withECDSA" -> {
                return 64;
            }
            case "SHA384withECDSA" -> {
                return 96;
            }
            case "SHA512withECDSA" -> {
                return 132;
            }
            default -> throw new IllegalArgumentException("Unsupported ECDSA algorithm");
        }
    }

    public boolean verifyPS256(String jwt, String signature) {
        return verifyPS(jwt, signature, PS_SIGNATURE_ALGORITHM_SHA256, rsaPublicKey);
    }

    public boolean verifyPS384(String jwt, String signature) {
        return verifyPS(jwt, signature, PS_SIGNATURE_ALGORITHM_SHA384, rsaPublicKey);
    }

    public boolean verifyPS512(String jwt, String signature) {
        return verifyPS(jwt, signature, PS_SIGNATURE_ALGORITHM_SHA512, rsaPublicKey);
    }

    public boolean verifyRS256(String jwt, String signature) {
        return verifyRS(jwt, signature, RS_SIGNATURE_ALGORITHM_SHA256, rsaPublicKey);
    }

    public boolean verifyRS384(String jwt, String signature) {
        return verifyRS(jwt, signature, RS_SIGNATURE_ALGORITHM_SHA384, rsaPublicKey);
    }

    public boolean verifyRS512(String jwt, String signature) {
        return verifyRS(jwt, signature, RS_SIGNATURE_ALGORITHM_SHA512, rsaPublicKey);
    }

    public boolean verifyES256(String jwt, String signature) {
        return verifyES(jwt, signature, ES_SIGNATURE_ALGORITHM_SHA256, ECpublicKey);
    }

    public boolean verifyES384(String jwt, String signature) {
        return verifyES(jwt, signature, ES_SIGNATURE_ALGORITHM_SHA384, ECpublicKey);
    }

    public boolean verifyES512(String jwt, String signature) {
        return verifyES(jwt, signature, ES_SIGNATURE_ALGORITHM_SHA512, ECpublicKey);
    }

    public boolean isValidBase64Url(String data) {
        String base64UrlPattern = "^[A-Za-z0-9-_]+$";

        Pattern pattern = Pattern.compile(base64UrlPattern);
        Matcher matcher = pattern.matcher(data);
        return matcher.matches();
    }

    private String encodeBase64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private String encodeNormalBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public byte[] decodeBase64Url(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    private String privateKeyToPEM(PrivateKey privateKey) {
        try {
            if (privateKey instanceof ECPrivateKey) {
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ECprivateKey.getEncoded());
                return "-----BEGIN PRIVATE KEY-----\n"
                        + encodeNormalBase64(pkcs8EncodedKeySpec.getEncoded())
                        + "\n-----END PRIVATE KEY-----";
            } else if (privateKey instanceof RSAPrivateKey) {
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
                return "-----BEGIN PRIVATE KEY-----\n"
                        + encodeNormalBase64(pkcs8EncodedKeySpec.getEncoded())
                        + "\n-----END PRIVATE KEY-----";
            } else {
                throw new IllegalArgumentException("Unsupported private key type.");
            }
        } catch (IllegalArgumentException ex) {
            return ex.getLocalizedMessage();
        }
    }

    private String publicKeyToPEM(PublicKey publicKey) {
        try {
            if (publicKey instanceof ECPublicKey) {
                X509EncodedKeySpec spec = new X509EncodedKeySpec(ECpublicKey.getEncoded());
                return "-----BEGIN PUBLIC KEY-----\n"
                        + encodeNormalBase64(spec.getEncoded())
                        + "\n-----END PUBLIC KEY-----";
            } else if (publicKey instanceof RSAPublicKey) {
                X509EncodedKeySpec spec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
                return "-----BEGIN PUBLIC KEY-----\n"
                        + encodeNormalBase64(spec.getEncoded())
                        + "\n-----END PUBLIC KEY-----";
            } else {
                throw new IllegalArgumentException("Unsupported public key type.");
            }
        } catch (IllegalArgumentException ex) {
            return ex.getMessage();
        }
    }

    private String getPEM(PrivateKey privateKey, PublicKey publicKey) {
        try {
            if (privateKey != null && publicKey == null) {
                return privateKeyToPEM(privateKey);
            } else if (privateKey == null && publicKey != null) {
                return publicKeyToPEM(publicKey);
            }
        } catch (Exception ex) {
            return ex.getMessage();
        }
        return null;
    }

    public String getPrivateKeyPEM() {
        return privateKeyPEM;
    }

    public String getPublicKeyPEM() {
        return publicKeyPEM;
    }

}
