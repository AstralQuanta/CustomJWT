# 基于 Java 的 (JWT) JSON Web Token 安全验证 - [English Doc](https://github.com/AstralQuanta/CustomJWT/blob/main/README.md)
[![Apache Java](https://img.shields.io/badge/logo-apache-yellow?logo=apache-maven)](https://www.apache.org/foundation/marks/)
[![License](http://img.shields.io/:license-apache-green.svg?style=flat)](https://www.apache.org/licenses/)
![Maven Central](https://img.shields.io/maven-central/v/top.pulselink.java/customjwt)
![image](https://github.com/blueokanna/CustomJWT/assets/56761243/5c553ae7-8dc5-46d8-8032-fabd989dc51b)
[![Hits](https://hits.sh/github.com/blueokanna/CustomJWT.git.svg?color=fe7d37)](https://hits.sh/github.com/blueokanna/CustomJWT.git/)

## 使用文档
>  JWT（JSON Web Token）是一种基于 JSON 的开放标准，用于在网络应用程序之间安全传输信息。它包含头部、载荷和签名三个部分，采用数字签名或消息认证码验证信息完整性和真实性。相较于传统的 Cookie 和 Session 认证方式，JWT 具有更节约资源、对移动端和分布式系统友好等优点。

### 设备环境要求

本项目使用的是 **Java JDK LTS 17** ，请使用相同版本的 **JDK** 或更高版本支持此库。 对于 **17** 以上的非 **LTS** 版本的问题，将根据具体的运行环境情况予以考虑。

`CustomJWT` 目前支持以下签名和验证算法：

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


> 注意❗ 对具有曲线 secp256k1 和 SHA-256 (ES256K) 的 ECDSA 的支持在 JDK15 就已经被删除了，如果需要修改相关的代码，那么就要注意了！
> 
> :warning:  **重要安全说明:** JVM 存在 ECDSA 算法的严重漏洞- [CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449).请尽快检查你的设备是否更新！

### 调用 Java 库

**Java Maven** 调用本次项目的库：
```java
<dependency>
  <groupId>top.pulselink.java</groupId>
  <artifactId>customjwt</artifactId>
  <version>1.0.0</version>
</dependency>
```

**Java Gradle** 调用本次项目的库：
```java
implementation group: 'top.pulselink.java', name: 'customjwt', version: '1.0.0'
```

**Java ivy** 调用本次项目的库：
```java
<dependency org="top.pulselink.java" name="customjwt" rev="1.0.0"/>
```

### 使用 Java-CustomJWT 库
使用 **`CustomJWT jwt = new CustomJWT()`** 初始化这个库，配置声明等。

下面的示例使用各种支持的签名算法：

**1. HS256 签名算法:**
```java
public static void main(String [] args){

try{
 CustomJWT jwt = new CustomJWT();  //初始化

/*
准备Header
*/

 String alg = "HS256";              //添加 Header
 String type = "JWT";               //添加Header
 String header = jwt.Header(alg, type);      //给 header 添加进这两个元素

/*
准备Payload
*/

  String[] payloadMessage = {
                    "sub", "1234567890",                //1
                    "name", "John Doe",                 //2
                    "admin", "true",                    //3
                    "iat", Long.toString(1516239022L)    //4
                };                                      //准备好将 payload 的消息

/*
以下的isNumArray 这里的 `true` 是将 payload 里面的 `boolean` 类型和长整型生成对应的类型，
比如在 payload 里面的 `1` 这一行的注释输出的希望得到的是字符串类型，则直接输出 `false`，如果要输出为整数类型，则修改为 `true` 就行
比如这里的 `"admin", "true"`这里是将字符串来的 `true` 转变成 `boolean` 的类型.
显示将不带引号，同样的长整数类型同样也是这个道理，输出不为字符串类型
*/

 boolean[] isNumArray = {false, false, true, true};
 String payload = jwt.Payload(isNumArray, payloadMessage); //将消息添加到 Payload 部分

/*
准备Sign
*/

 String key = "your-256-bit-secret";  //给下面的签名部分添加 secret
 String sign = jwt.Signature(alg, header + "." + payload, key); //准备给 header 和 payload 生成签名

 System.out.println(header + "." + payload + "." + sign);  // JWT 生成，输出 Token
 System.out.println(jwt.verifyHS(header + "." + payload + "." + sign, alg, key));   //输出 HS256 JWT 的验证，如果验证正确则输出true,否则输出false

  }catch(Exception ex){
    ex.printStackTrace();
  }
}
```

**2. PS256 签名算法:**

```java
public static void main(String [] args){

try{
 CustomJWT jwt = new CustomJWT(2048);  // RSA2048 初始化

/*
准备Header
*/

 String alg = "PS256";              //添加 Header
 String type = "JWT";               //添加Header
 String header = jwt.Header(alg, type);      //给 header 添加进这两个元素

/*
准备Payload
*/

  String[] payloadMessage = {
                    "sub", "1234567890",                //1
                    "name", "John Doe",                 //2
                    "admin", "true",                    //3
                    "iat", Long.toString(1516239022L)    //4
                };                                      //准备好将 payload 的消息

/*
以下的isNumArray 这里的 `true` 是将 payload 里面的 `boolean` 类型和长整型生成对应的类型，
比如在 payload 里面的 `1` 这一行的注释输出的希望得到的是字符串类型，则直接输出 `false`，如果要输出为整数类型，则修改为 `true` 就行
比如这里的 `"admin", "true"`这里是将字符串来的 `true` 转变成 `boolean` 的类型.
显示将不带引号，同样的长整数类型同样也是这个道理，输出不为字符串类型
*/

 boolean[] isNumArray = {false, false, true, true};
 String payload = jwt.Payload(isNumArray, payloadMessage); //将消息添加到 Payload 部分

/*
准备Sign
*/

 String sign = jwt.Signature(alg, header + "." + payload); //准备给 header 和 payload 生成签名

System.out.println("Private Key (PEM):");
System.out.println(jwt.getPrivateKeyPEM());      //输出 RSAPSSSHA256withMGF1 的私钥签名
System.out.println();

System.out.println("Public Key (PEM):");
System.out.println(jwt.getPublicKeyPEM());      //输出 RSAPSSSHA256withMGF1 的公钥签名
System.out.println();


 System.out.println(header + "." + payload + "." + sign);  // JWT 生成，输出 Token
 System.out.println(jwt.verifyPS256(header + "." + payload + "." + sign, sign));   //输出 PS256 JWT 的验证，如果验证正确则输出true,否则输出false

  }catch(Exception ex){
    ex.printStackTrace();
  }
}
```

**3. RS256 签名算法:(与 PS256 差不多)**

```java
public static void main(String [] args){

try{
 CustomJWT jwt = new CustomJWT(2048);  // RSA2048 初始化

/*
准备Header
*/

 String alg = "RS256";              //添加 Header
 String type = "JWT";               //添加Header
 String header = jwt.Header(alg, type);      //给 header 添加进这两个元素

/*
准备Payload
*/

  String[] payloadMessage = {
                    "sub", "1234567890",                //1
                    "name", "John Doe",                 //2
                    "admin", "true",                    //3
                    "iat", Long.toString(1516239022L)    //4
                };                                      //准备好将 payload 的消息

/*
以下的isNumArray 这里的 `true` 是将 payload 里面的 `boolean` 类型和长整型生成对应的类型，
比如在 payload 里面的 `1` 这一行的注释输出的希望得到的是字符串类型，则直接输出 `false`，如果要输出为整数类型，则修改为 `true` 就行
比如这里的 `"admin", "true"`这里是将字符串来的 `true` 转变成 `boolean` 的类型.
显示将不带引号，同样的长整数类型同样也是这个道理，输出不为字符串类型
*/

 boolean[] isNumArray = {false, false, true, true};
 String payload = jwt.Payload(isNumArray, payloadMessage); //将消息添加到 Payload 部分

/*
准备Sign
*/

 String sign = jwt.Signature(alg, header + "." + payload); //准备给 header 和 payload 生成签名

System.out.println("Private Key (PEM):");
System.out.println(jwt.getPrivateKeyPEM());      //输出 SHA256withRSA 的私钥签名
System.out.println();

System.out.println("Public Key (PEM):");
System.out.println(jwt.getPublicKeyPEM());      //输出 SHA256withRSA 的公钥签名
System.out.println();


 System.out.println(header + "." + payload + "." + sign);  // JWT 生成，输出 Token
 System.out.println(jwt.verifyRS256(header + "." + payload + "." + sign, sign));   //输出 RS256 JWT 的验证，如果验证正确则输出true,否则输出false

  }catch(Exception ex){
    ex.printStackTrace();
  }
}
```

**3. ES256 签名算法:(ECDSA 椭圆算法)**

```java
public static void main(String [] args){

try{
 CustomJWT jwt = new CustomJWT(256);  // ECDSA 初始化，这里提供的有256，384，521

/*
准备Header
*/

 String alg = "ES256";              //添加 Header
 String type = "JWT";               //添加Header
 String header = jwt.Header(alg, type);      //给 header 添加进这两个元素

/*
准备Payload
*/

  String[] payloadMessage = {
                    "sub", "1234567890",                //1
                    "name", "John Doe",                 //2
                    "admin", "true",                    //3
                    "iat", Long.toString(1516239022L)    //4
                };                                      //准备好将 payload 的消息

/*
以下的isNumArray 这里的 `true` 是将 payload 里面的 `boolean` 类型和长整型生成对应的类型，
比如在 payload 里面的 `1` 这一行的注释输出的希望得到的是字符串类型，则直接输出 `false`，如果要输出为整数类型，则修改为 `true` 就行
比如这里的 `"admin", "true"`这里是将字符串来的 `true` 转变成 `boolean` 的类型.
显示将不带引号，同样的长整数类型同样也是这个道理，输出不为字符串类型
*/

 boolean[] isNumArray = {false, false, true, true};
 String payload = jwt.Payload(isNumArray, payloadMessage); //将消息添加到 Payload 部分

/*
准备Sign
*/

String sign = jwt.Signature(alg, header + "." + payload); //准备给 header 和 payload 生成签名

System.out.println("Private Key (PEM):");
System.out.println(jwt.getPrivateKeyPEM());      //输出 SHA256withECDSA 的私钥签名
System.out.println();

System.out.println("Public Key (PEM):");
System.out.println(jwt.getPublicKeyPEM());      //输出 SHA256withECDSA 的公钥签名
System.out.println();


 System.out.println(header + "." + payload + "." + sign);  // JWT 生成，输出 Token
 System.out.println(jwt.verifyES256(header + "." + payload + "." + sign, sign));   //输出 RS256 JWT 的验证，如果验证正确则输出true,否则输出false

  }catch(Exception ex){
    ex.printStackTrace();
  }
}
```
## 问答

Q: 对比 RS256 和 PS256 的区别：

> PS256和RS256都使用RSA算法，但PS256使用了更加安全和复杂的RSA-PSS签名方案，相对于传统的RS256签名提供了更多的安全性和防护。在实际应用中，PS256通常被认为是更安全的选择，尤其是在对安全性要求较高的环境中。

Q: HS256的安全性比RS256或者是PS256高吗？

> HS256的安全性取决于密钥的保护和管理。如果密钥不被泄露且足够强大，则HMAC算法可以提供良好的安全性。
>
> RS256和PS256使用非对称密钥对，因此相对于HMAC，它们不需要在通信双方共享密钥。这使得密钥管理变得更容易，但是需要更多的计算资源来生成和验证签名。而且，PS256相对于RS256提供了更强的安全性，特别是对于一些攻击类型有更好的防护。安全性的比较取决于实际的使用场景和密钥管理的方式。如果密钥可以被安全地管理且足够强大，HMAC算法提供的安全性可以与非对称加密算法媲美。
>
> 但在许多情况下，非对称加密算法如RS256或者PS256被认为提供了更好的安全性，特别是在密钥管理复杂或者需要更高级的安全保护时。

Q: ES256算法在什么情况下最有用？

> 移动设备和资源受限设备：椭圆曲线加密算法相比传统的RSA算法具有更小的密钥尺寸，因此在资源受限的环境（如移动设备、传感器、物联网设备等）中更为适用。它需要更少的计算资源和存储空间，同时提供了相当的安全性，这使得ES256成为这些设备上的理想选择。
>
> 网络带宽受限的环境：ES256生成的签名相对于RSA算法生成的签名更短，这意味着在网络传输中占用更少的带宽。在网络带宽受限的情况下，使用ES256可以减少传输开销。
> 
> 对安全性和效率都有要求的场景：ES256提供了与RSA相当的安全性，同时在资源消耗和效率方面更具优势。因此，在需要保证安全性的同时，也需要考虑资源消耗和性能的场景下，ES256是一个很好的选择。
> 
> 需要强大安全性的应用场景：椭圆曲线加密算法通常被认为比RSA算法更强大，因为它们提供了相同或更高级别的安全性，同时使用更短的密钥长度。因此，对于需要高级别安全保护的应用场景，ES256是一个有吸引力的选择。
> 
> ES256 这个算法在资源受限或者对安全性和效率都有要求的环境下，它能提供良好的安全性，并在资源消耗方面有一定的优势。

## 问题反馈与贡献赞助支持

### 问题反馈准则

您可以在 Github Issue 处报告项目的安全漏洞。这边也会努力确保及时处理问题，但根据不同时区的时间影响，可能需要一段时间才能即使回复或者更新代码。


----
















