# Custom Java-based (JWT) JSON Web Token security verification - [中文文档](https://github.com/AstralQuanta/CustomJWT/blob/main/README_zh.md)
[![Apache Java](https://img.shields.io/badge/logo-apache-yellow?logo=apache-maven)](https://www.apache.org/foundation/marks/)
[![License](http://img.shields.io/:license-apache-green.svg?style=flat)](https://www.apache.org/licenses/)
![Maven Central](https://img.shields.io/maven-central/v/top.pulselink.java/customjwt)
![image](https://github.com/blueokanna/CustomJWT/assets/56761243/5c553ae7-8dc5-46d8-8032-fabd989dc51b)
[![Hits](https://hits.sh/github.com/blueokanna/CustomJWT.git.svg?color=fe7d37)](https://hits.sh/github.com/blueokanna/CustomJWT.git/)

## Documentation
>  JWT (JSON Web Token) is an open standard based on JSON for securely transmitting information between web applications. It contains three parts: header, payload and signature, and uses digital signature or message authentication code to verify the integrity and authenticity of the information. Compared with traditional Cookie and Session authentication methods, JWT has the advantages of being more resource-saving and friendly to mobile terminals and distributed systems.

### Environmental requirements for equipment

This project uses **Java JDK LTS 17**, please use the same version of **JDK** or higher to support this library. Issues with non-**LTS** versions above **17** will be considered on a case-by-case basis.

`CustomJWT` currently supports the following signature and verification algorithms：

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| HS256 | HMAC256 | HMAC with SHA-256 |
| HS384 | HMAC384 | HMAC with SHA-384 |
| HS512 | HMAC512 | HMAC with SHA-512 |
| PS256 | RSA256 | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 |
| PS384 | RSA384 | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 |
| PS512 | RSA512 | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | RSA384 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | RSA512 | RSASSA-PKCS1-v1_5 with SHA-512 |
| ES256 | ECDSA256 | ECDSA with curve P-256 and SHA-256 |
| ES384 | ECDSA384 | ECDSA with curve P-384 and SHA-384 |
| ES512 | ECDSA512 | ECDSA with curve P-521 and SHA-512 |


> Causion❗ Support for ECDSA with curves secp256k1 and SHA-256 (ES256K) was removed in JDK15, so be careful if you need to modify the relevant code!！
> 
> :warning:  **Important Security Note:** A critical vulnerability exists in the JVM for the ECDSA algorithm - [CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449). Please check your device for updates as soon as possible!

### Java Libraries

**Java Maven** for this project：
```java
<dependency>
  <groupId>top.pulselink.java</groupId>
  <artifactId>customjwt</artifactId>
  <version>1.0.0</version>
</dependency>
```

**Java Gradle** for this project：
```java
implementation group: 'top.pulselink.java', name: 'customjwt', version: '1.0.0'
```

**Java ivy** for this project：
```java
<dependency org="top.pulselink.java" name="customjwt" rev="1.0.0"/>
```

### Use Java-CustomJWT Library
**`CustomJWT jwt = new CustomJWT()`** Initialise this library, configure declarations etc.

**The following examples use various supported signature algorithms:**

**1. HS256 signature algorithm:**
```java
public static void main(String [] args){

try{
 CustomJWT jwt = new CustomJWT();  //initialisation

/*
Prepare Header
*/

 String alg = "HS256";              //Add Header
 String type = "JWT";               //Add Header
 String header = jwt.Header(alg, type);      //Add these two elements to the header

/*
Prepare Payload
*/

  String[] payloadMessage = {
                    "sub", "1234567890",                //1
                    "name", "John Doe",                 //2
                    "admin", "true",                    //3
                    "iat", Long.toString(1516239022L)    //4
                };                                      //Prepare the message for the payload

/*
The `true` in the following isNumArray is to generate the corresponding type for the `boolean` type and the long integer type inside the payload, for example, if the comment on the line `1` inside the payload wants to get the string type, it will output `false` directly.

For example, if you want to get a string type in the comment output of the line `1` inside the payload, you can output `false` directly, if you want to output an integer type, you can change it to `true`.

For example, `"admin", "true"` here is to convert the string `true` to a `boolean` type.

The display will be without quotes, and the same applies to long integer types, the output will not be of string type.
*/

 boolean[] isNumArray = {false, false, true, true};
 String payload = jwt.Payload(isNumArray, payloadMessage); //Add the message to the Payload section

/*
Prepare Sign
*/

 String key = "your-256-bit-secret";  //add secret to the signature section below
 String sign = jwt.Signature(alg, header + "." + payload, key); //Prepare to generate signatures for the header and payload.

 System.out.println(header + "." + payload + "." + sign);  // JWT generation, output Token
 System.out.println(jwt.verifyHS(header + "." + payload + "." + sign, alg, key));   //Output the validation of HS256 JWT, if the validation is correct then output true, otherwise output false.

  }catch(Exception ex){
    ex.printStackTrace();
  }
}
```

**2. PS256 signature algorithm:**

```java
public static void main(String [] args){

try{
 CustomJWT jwt = new CustomJWT(2048);  // RSA2048 Initialisation

/*
Prepare Header
*/

 String alg = "PS256";              //Add Header
 String type = "JWT";               //Add Header
 String header = jwt.Header(alg, type);      //Add these two elements to the header

/*
Prepare Payload
*/

  String[] payloadMessage = {
                    "sub", "1234567890",                //1
                    "name", "John Doe",                 //2
                    "admin", "true",                    //3
                    "iat", Long.toString(1516239022L)    //4
                };                                      //Prepare the message for the payload

/*
The `true` in the following isNumArray is to generate the corresponding type for the `boolean` type and the long integer type inside the payload, for example, if the comment on the line `1` inside the payload wants to get the string type, it will output `false` directly.

For example, if you want to get a string type in the comment output of the line `1` inside the payload, you can output `false` directly, if you want to output an integer type, you can change it to `true`.

For example, `"admin", "true"` here is to convert the string `true` to a `boolean` type.

The display will be without quotes, and the same applies to long integer types, the output will not be of string type.
*/

 boolean[] isNumArray = {false, false, true, true};
 String payload = jwt.Payload(isNumArray, payloadMessage); //Add the message to the Payload section

/*
Prepare Sign
*/

 String sign = jwt.Signature(alg, header + "." + payload); //Prepare to generate signatures for the header and payload

System.out.println("Private Key (PEM):");
System.out.println(jwt.getPrivateKeyPEM());      //Output RSAPSSSHA256withMGF1 Private Key Signature
System.out.println();

System.out.println("Public Key (PEM):");
System.out.println(jwt.getPublicKeyPEM());      //Output RSAPSSSHA256withMGF1 Public Key Signature
System.out.println();


 System.out.println(header + "." + payload + "." + sign);  // JWT generation, output Token
 System.out.println(jwt.verifyPS256(header + "." + payload + "." + sign, sign));   //Output the validation of PS256 JWT, if the validation is correct then output true, otherwise output false.

  }catch(Exception ex){
    ex.printStackTrace();
  }
}
```

**3. RS256 signature algorithm: **

```java
public static void main(String [] args){

try{
 CustomJWT jwt = new CustomJWT(2048);  // RSA2048 Initialisation

/*
Prepare Header
*/

 String alg = "RS256";              //Add Header
 String type = "JWT";               //Add Header
 String header = jwt.Header(alg, type);      //Add these two elements to the header

/*
Prepare Payload
*/

  String[] payloadMessage = {
                    "sub", "1234567890",                //1
                    "name", "John Doe",                 //2
                    "admin", "true",                    //3
                    "iat", Long.toString(1516239022L)    //4
                };                                      //Prepare the message for the payload

/*
The `true` in the following isNumArray is to generate the corresponding type for the `boolean` type and the long integer type inside the payload, for example, if the comment on the line `1` inside the payload wants to get the string type, it will output `false` directly.

For example, if you want to get a string type in the comment output of the line `1` inside the payload, you can output `false` directly, if you want to output an integer type, you can change it to `true`.

For example, `"admin", "true"` here is to convert the string `true` to a `boolean` type.

The display will be without quotes, and the same applies to long integer types, the output will not be of string type.
*/

 boolean[] isNumArray = {false, false, true, true};
 String payload = jwt.Payload(isNumArray, payloadMessage); //Add the message to the Payload section

/*
准备Sign
*/

 String sign = jwt.Signature(alg, header + "." + payload); //Prepare to generate signatures for the header and payload

System.out.println("Private Key (PEM):");
System.out.println(jwt.getPrivateKeyPEM());      //Output SHA256withRSA private key signature
System.out.println();

System.out.println("Public Key (PEM):");
System.out.println(jwt.getPublicKeyPEM());      //Output SHA256withRSA public key signature
System.out.println();


 System.out.println(header + "." + payload + "." + sign);  // JWT generation, output Token
 System.out.println(jwt.verifyRS256(header + "." + payload + "." + sign, sign));   //Output the validation of RS256 JWT, if the validation is correct then output true, otherwise output false.

  }catch(Exception ex){
    ex.printStackTrace();
  }
}
```

**3. ES256 Signature Algorithm: (ECDSA Elliptic Algorithm)**

```java
public static void main(String [] args){

try{
 CustomJWT jwt = new CustomJWT(256);  // ECDSA initialisation, provided here with 256, 384, 521

/*
Prepare Header
*/

 String alg = "ES256";              //Add Header
 String type = "JWT";               //Add Header
 String header = jwt.Header(alg, type);      //Add these two elements to the header

/*
Prepare Payload
*/

  String[] payloadMessage = {
                    "sub", "1234567890",                //1
                    "name", "John Doe",                 //2
                    "admin", "true",                    //3
                    "iat", Long.toString(1516239022L)    //4
                };                                      //Prepare the message for the payload

/*
The `true` in the following isNumArray is to generate the corresponding type for the `boolean` type and the long integer type inside the payload, for example, if the comment on the line `1` inside the payload wants to get the string type, it will output `false` directly.

For example, if you want to get a string type in the comment output of the line `1` inside the payload, you can output `false` directly, if you want to output an integer type, you can change it to `true`.

For example, `"admin", "true"` here is to convert the string `true` to a `boolean` type.

The display will be without quotes, and the same applies to long integer types, the output will not be of string type.
*/

 boolean[] isNumArray = {false, false, true, true};
 String payload = jwt.Payload(isNumArray, payloadMessage); //Add the message to the Payload section

/*
Prepare Sign
*/

String sign = jwt.Signature(alg, header + "." + payload); //Prepare to generate signatures for the header and payload

System.out.println("Private Key (PEM):");
System.out.println(jwt.getPrivateKeyPEM());      //Output SHA256withECDSA private key signature
System.out.println();

System.out.println("Public Key (PEM):");
System.out.println(jwt.getPublicKeyPEM());      //Output SHA256withECDSA Public Key Signature
System.out.println();


 System.out.println(header + "." + payload + "." + sign);  // JWT generation, output Token
 System.out.println(jwt.verifyES256(header + "." + payload + "." + sign, sign));   //Output the validation of RS256 JWT, if the validation is correct then output true, otherwise output false.

  }catch(Exception ex){
    ex.printStackTrace();
  }
}
```
## Q & A

**Q: Compare the difference between RS256 and PS256:**

> A: Both PS256 and RS256 use the RSA algorithm, but PS256 uses a more secure and sophisticated RSA-PSS signature scheme, which provides more security and protection compared to the traditional RS256 signature. In practice, PS256 is often considered the more secure choice, especially in environments with high security requirements.

**Q: Is HS256 more secure than RS256 or PS256?**

> A: The security of HS256 depends on key protection and management. The HMAC algorithm provides good security if the key is not compromised and is strong enough.
>
> RS256 and PS256 use asymmetric key pairs, so they do not need to share the key between the two communicating parties as opposed to HMAC. This makes key management easier, but requires more computational resources to generate and verify signatures. Also, PS256 provides stronger security compared to RS256, especially better protection against some types of attacks.
Overall, the security comparison depends on the actual usage scenario and the way the key is managed. If the keys can be managed securely and are strong enough, the HMAC algorithm provides security comparable to asymmetric encryption algorithms.
>
> In many cases, asymmetric encryption algorithms such as RS256 or PS256 are considered to provide better security, especially when key management is complex or more advanced security is required.

**Q: In what situations is the ES256 algorithm most useful?**

> A: Mobile and resource-constrained devices: Elliptic curve encryption algorithms have smaller key sizes than traditional RSA algorithms, making them more useful in resource-constrained environments (e.g., mobile devices, sensors, IoT devices, etc.). It requires fewer computational resources and storage space while providing comparable security, which makes ES256 an ideal choice on these devices.
>
> Network bandwidth-constrained environments: ES256-generated signatures are shorter compared to signatures generated by the RSA algorithm, which means they take up less bandwidth in network transmissions. In network bandwidth-constrained environments, using ES256 reduces transmission overhead.
>
> Scenarios requiring both security and efficiency: ES256 provides comparable security to RSA, while taking advantage of resource consumption and efficiency. Therefore, ES256 is a good choice for scenarios where security needs to be ensured while resource consumption and performance need to be considered.
>
> Application scenarios requiring strong security: Elliptic curve encryption algorithms are often considered stronger than RSA algorithms because they provide the same or higher level of security while using shorter key lengths. Therefore, ES256 is an attractive choice for application scenarios that require a high level of security.
>
> ES256 This algorithm provides good security in resource-constrained environments or environments where both security and efficiency are required, and has some advantages in terms of resource consumption.


## Issue Feedback and Contribution Sponsorship Support

### Guidelines for feedback on issues

You can report security vulnerabilities in your project at Github Issues. We'll try to make sure the issue is handled in a timely manner, but depending on the time impact of different time zones, it may take a while before we can even respond or update the code.


----
















