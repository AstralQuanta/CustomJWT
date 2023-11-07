# 基于 Java 的 (JWT) JSON Web Token 安全验证
[![License](http://img.shields.io/:license-apache-blue.svg?style=flat)](https://www.apache.org/licenses/)


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

## 问题反馈与贡献赞助支持

### 问题反馈准则

> 您可以在 Github Issue 处报告项目的安全漏洞。这边也会努力确保及时处理问题，但根据不同时区的时间影响，可能需要一段时间才能即使回复或者更新代码。

### 贡献与赞助支持
首先先感谢对此项目 CustomJWT 的支持与贡献！
> 赞助 Doge 地址： D7QJGmzurVpuG5uaxqSccMv3c1VX76HwZP
>
> 赞助 Firo 地址：aFGoWQhsTXutfCotGjxp5VTgc8Wjn5X53z
>
> 赞助 XMR 地址：41yBawyNRSfe7X6G4RKjKQZXZMDfe1JCnBynsXSNEjPq8dsXYevLv4pBGbmqY6yRSsYLd1g4xyuLYiwxEAC8YSyD4fxZSNJ
>
----
















