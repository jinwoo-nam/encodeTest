import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:pointycastle/asymmetric/api.dart';
import 'package:crypto/crypto.dart';
import 'package:fast_rsa/fast_rsa.dart' as fast_rsa;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({Key? key, required this.title}) : super(key: key);

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            ElevatedButton(
              onPressed: utf8Encode,
              child: const Text('UTF8 encode'),
            ),
            ElevatedButton(
              onPressed: base64Encode,
              child: const Text('BASE64 encode'),
            ),
            ElevatedButton(
              onPressed: zLibInflate,
              child: const Text('ZLib encode'),
            ),
            ElevatedButton(
              onPressed: hmacEncode,
              child: const Text('HMAC encode'),
            ),
            ElevatedButton(
              onPressed: aesEncode,
              child: const Text('AES encode'),
            ),
            ElevatedButton(
              onPressed: rsaEncrypt,
              child: const Text('RSA encode'),
            ),
            ElevatedButton(
              onPressed: rsaEncrypt2,
              child: const Text('RSA encode2'),
            ),
          ],
        ),
      ),
    );
  }

  void utf8Encode() {
    String message = 'message 입니다.-UTF8';
    List<int> encode = utf8.encode(message);
    print(encode);
    String decode = utf8.decode(encode);
    print(decode);
  }

  void base64Encode() {
    //String message = 'message 입니다.-BASE64';
    //String encode = base64.encode(utf8.encode(message));
    //String encode = base64.encode(test);
    //print('base64: $encode');
    // String encode =
    //     'q1YqLc1MSVSyUjI1TrE0SE400TW1SLXUNTRMTdG1TDJL1DUwMjFKTDY0MjAwMFLSAStPIl55TmJJZklpSqqSlaGBAZCbn5eOEKgFAA==';

    // List<int> decode = base64.decode(encode);
    // print('decode : $decode');
    //print(utf8.decode(decode));
  }

  void zLibInflate() {
    String test = jsonEncode({
      "uuida": "53d90ca4-58e9-11ed-9b6a-0242ac120002",
      "uuidb": "53d90ca4-58e9-11ed-9b6a-0242ac120002",
      "latitude": 100,
      "longtitude": 10
    });
    //print(test);
    String message = test;
    //List<int> encode = zlib.encode(utf8.encode(message));
    List<int> GEncode = gzip.encode(utf8.encode(message));
    List<int> ZEncode = zlib.encode(utf8.encode(message));
    print('gzip encode $GEncode');
    print('zlib encode $ZEncode');
    List<int> GDecode = zlib.decode(GEncode);
    List<int> ZDecode = zlib.decode(GEncode);
    //print(decode);
    print(utf8.decode(GDecode));
    print(utf8.decode(ZDecode));
  }

  void hmacEncode() {
    String key = 'o20holr15p04o0611z54g10wp';
    String message = 'message 입니다.-HMAC';
    final hmacSha256 = Hmac(sha256, utf8.encode(key));
    final digest = hmacSha256.convert(utf8.encode(message));

    print(digest.bytes);
    print(digest);
  }

  void aesEncode() {
    String message = 'message 입니다.-AES';
    //final key = encrypt.Key.fromSecureRandom(32);
    final key = encrypt.Key(
        utf8.encode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') as Uint8List);

    //final iv = encrypt.IV.fromSecureRandom(16);
    final iv = encrypt.IV(utf8.encode('bbbbbbbbbbbbbbbb') as Uint8List);

    final encryptor =
        encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
    final encrypted = encryptor.encrypt(message, iv: iv);
    print(encrypted.base64);

    final decrypted = encryptor.decrypt(encrypted, iv: iv);
    print(decrypted);
  }

  void rsaEncrypt() {
    String message = 'message 입니다.-RSA';
    final parser = encrypt.RSAKeyParser();
    final publicKey = parser.parse(publicKeyPem) as RSAPublicKey;
    final privateKey = parser.parse(privateKeyPem) as RSAPrivateKey;

    encrypt.Encrypter encryptor;
    encrypt.Encrypted encrypted;
    String decrypted;

    encryptor = encrypt.Encrypter(encrypt.RSA(
      publicKey: publicKey,
      privateKey: privateKey,
    ));
    encrypted = encryptor.encrypt(message);
    print(encrypted.base64);

    decrypted = encryptor.decrypt(encrypted);
    print(decrypted);

    //Signature & verify
    final signer = encrypt.Signer(
      encrypt.RSASigner(
        encrypt.RSASignDigest.SHA256,
        publicKey: publicKey,
        privateKey: privateKey,
      ),
    );

    encrypt.Encrypted signEncrypted = signer.sign(message);
    print(signEncrypted.base64);

    print(signer.verify64(message, signEncrypted.base64));
  }

  void rsaEncrypt2() async {
    //fast rsa lib test
    String password = '123456789';
    String message = 'test message';
    var encrypt = await fast_rsa.RSA
        .encryptPKCS1v15Bytes(utf8.encode(message) as Uint8List, publicKeyPem);
    print(encrypt);
    print(base64.encode(encrypt));

    var decrypt =
        await fast_rsa.RSA.decryptPKCS1v15Bytes(encrypt, privateKeyPem);
    print(decrypt);
    print(utf8.decode(decrypt));

    var signString = await fast_rsa.RSA
        .signPKCS1v15(message, fast_rsa.Hash.SHA256, privateKeyPem);
    print(signString);

    var signByte = await fast_rsa.RSA.signPKCS1v15Bytes(
        utf8.encode(message) as Uint8List, fast_rsa.Hash.SHA256, privateKeyPem);
    print(base64.encode(signByte));

    var verifySign1 = await fast_rsa.RSA.verifyPKCS1v15(
        signString, message, fast_rsa.Hash.SHA256, publicKeyPem);
    print(verifySign1);

    var verifySign2 = await fast_rsa.RSA.verifyPKCS1v15Bytes(signByte,
        utf8.encode(message) as Uint8List, fast_rsa.Hash.SHA256, publicKeyPem);
    print(verifySign2);

    var publicKeyConvert =
        await fast_rsa.RSA.convertPrivateKeyToPublicKey(privateKeyPem);
    print(publicKeyConvert);

    var encodedPrivateKey = await fast_rsa.RSA
        .encryptPrivateKey(privateKeyPem, password, fast_rsa.PEMCipher.AES256);
    print(encodedPrivateKey);
    var decodedPrivateKey =
        await fast_rsa.RSA.decryptPrivateKey(encodedPrivateKey, password);
    print(decodedPrivateKey);
  }

  String publicKeyPem = '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtZSrtYAXkbYz83AjaBXo
8TvWr8iEFh0Kmduu0riTm2ddZqMXcXLoVEhUSn+2a0xRyRoGv3JuEwceRh4toXyu
kR3OrirgjfJJY4/b0nOnbxfPYmER3cXnpnSqtStCBLQahV1MjnaYLEiQGmfAakJC
GJIis+waCCJgB6s6j1WjSqBSZ+Fl3Khy4g731EnZxZKkzWMpzr5EIzZiOerI436E
dEstVrDkuET47rTQxr4krM9xypYcTIUOKB0ogmJTSZpJA5W3cv+StCqXzgFeZ1Bb
/dA/KCP7x6+okc4BAW3i2OVRogYVZsnw96vUq9BrOSlriMxLQbl70Xz1DTSX/nfR
AQIDAQAB
-----END PUBLIC KEY-----
''';

  String privateKeyPem = '''
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1lKu1gBeRtjPz
cCNoFejxO9avyIQWHQqZ267SuJObZ11moxdxcuhUSFRKf7ZrTFHJGga/cm4TBx5G
Hi2hfK6RHc6uKuCN8kljj9vSc6dvF89iYRHdxeemdKq1K0IEtBqFXUyOdpgsSJAa
Z8BqQkIYkiKz7BoIImAHqzqPVaNKoFJn4WXcqHLiDvfUSdnFkqTNYynOvkQjNmI5
6sjjfoR0Sy1WsOS4RPjutNDGviSsz3HKlhxMhQ4oHSiCYlNJmkkDlbdy/5K0KpfO
AV5nUFv90D8oI/vHr6iRzgEBbeLY5VGiBhVmyfD3q9Sr0Gs5KWuIzEtBuXvRfPUN
NJf+d9EBAgMBAAECggEABnBjNmh4bX5ckUFkwAgm3ocUsd8WcAJPoe0cYfSRp20e
7sjRyAAfJP37nziwK1XlgJAftSJFrP8Pn8TqMVPOjO7VqW9zzxTMbW9oiCn5wgLC
I+b1Tzv5Xvm8I/iIusn4Nsp8MIEcHFXmZklPlXUMCvsDqAWzVp6BcUQtK3AJ/ldp
yeXfDyv26gXenQtLoVg9t9Jv8w9Ud56Pof+X19VNTo7YabzWap9+YMGURPjdaXt+
9V2wkKNSf5s1SsvrViKZ3BxdejSDtYss/+oNl1JPE8n9Ilu5AUiCwmX8BlNubsC8
IV7M0aGOfdYrCm2TbVfOoqsuj45VZ/T1a0uWIHH5wQKBgQDZ+/d/Hwf2NAmSGdaC
Tsh2QJIBJ9huvDbiBSMdOFyWepsAJ+WN5oNllMyemdIoPLmGg248wHPopl4haE6u
oGC/pK0HafHs9MhcdvBGBK0AT1Nykph77WO6RnK3oGe0LoE8StXWwLirtXUDiijb
ZHO7if4Iymp83wr5tvtUGspy3QKBgQDVP3LUHqu2n2TxFXLTpfNDQJKdsRyFxBNp
O3l6Yd0RPYbfIP9Qtcllf84WIqmhaWBV0B33hlnxobkzYjR0aD2As0NHxBjkh4xA
SYMMxxxDqDON+lo4XI2UFmZ50B7F/4Wxh1V0zCPDV7tYxtGoLx7/eYnUAnIjtPBJ
vTfJZMR6dQKBgF67Oo67LJmZecNNiURt+n4xh4ILD+rnzq4g72amdM5MkAncTM2D
LP07UkVmscccxL+pZIHwXS7xBh1cmD0Zo5IFfdCoASQqKNzOL5MuOwTUdH5pKO1K
eDmengIhKpBKWY2bNB00+cxdenHEXAckO4t357doSCjmQX3OQKEHV43dAoGAEe6W
8l1t5Rp8O4WpNUEENsiMS7RkCJ+XXkcBDRiDpXp+B+9XaOsQd3eK1fOuPgOFdVHd
4z2p/Jaz4y1D6fIGEfeBFdzYlwcK9TD5Uy6/IrVXOH4v7gNiaGyFy4KDw/SbwnT1
669q5ndPKsT1RmZH/gWzYF+gR35kol7F/Sp7Fy0CgYEAw0TrhDzFx5ZxuRoorAmA
+2nprnZnPyK0U2BRKTUBm8LRVsVq47OPljg8TL/FA/iIBlEhdgpoFyfIGSYRqeIB
/gc3R9b1HKIXNpiBFeq23lGIy/xNfvLpfLkEg1FEtvKKOnUux4U/SMIj/rDzkzJe
9RA55QOR5jf0Q6/cjOKAxvM=
-----END PRIVATE KEY-----
''';
}
