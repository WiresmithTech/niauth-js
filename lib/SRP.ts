/**
 * @file SRP implementation
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */
'use strict';
import {BigInteger, RandomGenerator} from 'jsbn';
import {sha1} from './SHA1';
import {HashStringToByteArray, bigIntegerToBytes, xorHashStrings, byteArrayToHashString} from './Utils.ts';


var isBigInteger = function(x) {
   return (x instanceof BigInteger);
};

var areBigIntegers = function(...numbers: BigInteger[] ) {
   for (var i = 0; i < numbers.length; ++i) {
      if (!isBigInteger(numbers[i])) {
         return false;
      }
   }
   return true;
};

var isString = function(x) {
   return (typeof x === 'string');
};

var isArray = function(x) {
   return Array.isArray(x);
};

const rng: RandomGenerator = {
   nextBytes(bytes) {
         let byte_buffer = new Uint8Array(bytes);
         let random = window.crypto.getRandomValues(byte_buffer);
         for (let i = 0; i < bytes.length; i++) {
            bytes[i] = random[i];
         }
   }
}

/*
 * MGF1 mask generation function with SHA1 hash.
 */
async function MGF1SHA1(byteArray: Uint8Array): Promise<string> {
   var C1 = new Uint8Array([...byteArray, 0,0,0,0]);
   var C2 = new Uint8Array([...byteArray, 0,0,0,1]);
   return await sha1(C1) + await sha1(C2);
};

/**
 * SRP mathematical operations.
 *
 * Style note: These functions use a lot of single-character function and
 * variable names. This harkens back to the original Secure Remote Password
 * protocol paper. See http://srp.stanford.edu/ndss.html
 */
export class SRPOps {

   /**
    * Returns client's random number.
    * @returns {BigInteger}
    */
   static a(): BigInteger {
      return new BigInteger(512, rng);
   };

   static b(): BigInteger {
      return new BigInteger(512, rng);
   }

   /*
    * Calculates "A", public random number.
    * @param {BigInteger} N - A large safe prime
    * @param {BigInteger} g - A generator modulo N
    * @param {BigInteger} a - A random number
    * @returns {BigInteger} g^a % N
    */
   static A(N: BigInteger, g: BigInteger, a: BigInteger): BigInteger {
      if (!areBigIntegers(N, g, a)) {
         throw 'invalid argument: N, g and a should be big int for A';
      }

      return g.modPow(a, N);
   };

   /**
    * Calculates "B", public random number.
    * @param {BigInteger} N - A large safe prime
    * @param {BigInteger} g - A generator modulo N
    * @param {BigInteger} v - Password verifier
    * @param {BigInteger} b - A random number
    * @returns {BigInteger} k * v + g^b
    */
   static async B(N: BigInteger, g: BigInteger, v: BigInteger, b: BigInteger): Promise<BigInteger> {

      return (((await SRPOps.k(N, g)).multiply(v)).add(g.modPow(b, N))).mod(N);
   };

   /**
    * Calculates "u" random scrambling parameter.
    * u = SHA(A+B)
    * @param {BigInteger} A - Client public random number
    * @param {BigInteger} B - Client public random number
    * @returns {BigInteger} SHA(A+B)
    */
   static async u(A: BigInteger, B:BigInteger): Promise<BigInteger> {
      if (!areBigIntegers(A, B)) {
         throw 'invalid argument: A and B must be big int for u';
      }

      var Ab = bigIntegerToBytes(A, 128);
      var Bb = bigIntegerToBytes(B, 128);
      var ABb = new Uint8Array([...Ab, ...Bb]);
      let aBb_sha = await sha1(ABb);
      return new BigInteger(aBb_sha, 16);
   };

   /**
    * Calculates "k" multiplier number
    * k = SHA(N + PAD(g))
    * @param {BigInteger} N - A large safe prime
    * @param {BigInteger} g - a generator modulo N
    * @returns {BigInteger} SHA(N+PAD(g))
    */
   static async k(N: BigInteger, g: BigInteger): Promise<BigInteger> {
      if (!areBigIntegers(N, g)) {
         throw 'invalid argument: N and g must be big int for k.';
      }

      const Nb = bigIntegerToBytes(N, 128);
      const gb = bigIntegerToBytes(g, 128);
      const Ngb = new Uint8Array([...Nb, ...gb]);
      const Ngb_sha = await sha1(Ngb);
      return new BigInteger(Ngb_sha, 16);
   };

   /**
    * Calculates the value of "x" private key derived from username,
    * password, and salt.
    * x = SHA(salt + SHA(username + ":" + assword))
    * @param {byte array} salt User's salt
    * @param {string} username User's name
    * @param {string} password User's password
    * returns {BigInteger} SHA(salt + SHA(username + ":" + password))
    */
   static async x(salt: Uint8Array, username: string, password: string): Promise<BigInteger> {
      var user = username || '';
      var pass = password || '';

      if (!SRPOps.isUint8Array(salt)) {
         throw 'invalid argument: salt must be byte array for x';
      }
      if (!isString(user) || !isString(pass)) {
         throw 'invalid argument: User and password must be string for x';
      }

      const concat1 = (user + ':' + pass);
      const concat1_sha = await sha1(concat1);
      const concat1_sha_bytes = HashStringToByteArray(concat1_sha);
      const concat2 = new Uint8Array([...salt, ...concat1_sha_bytes]);
      const concat2_sha = await sha1(concat2);
      return new BigInteger(concat2_sha, 16);
   };

   /**
    * Calculates the client side value of "S".
    * @param {BigInteger} N - A large safe prime
    * @param {BigInteger} g - A generator modulo N
    * @param {BigInteger} B - Server's public random number
    * @param {BigInteger} k - Multiplier parameter
    * @param {BigInteger} x - Private key
    * @param {BigInteger} a - Client's private random number
    * @param {BigInteger} u - Random scrambling parameter
    * @returns {BigInteger} (B - g^x) ^ (a + u * x) % N
    */
   static Sc(N: BigInteger, g: BigInteger, B: BigInteger, k: BigInteger, x: BigInteger, a: BigInteger, u: BigInteger): BigInteger {
      if (!areBigIntegers(N, g, B, k, x, a, u)) {
         throw 'invalid argument: N, g, B, k, x, a, u bust be big ints for Sc';
      }

      return (B.add(k.multiply(N.subtract(g.modPow(x, N))).mod(N))).modPow(a.add(u.multiply(x)), N);
   };

   /**
    * Calculates the server side value of "S"
    * @param {BigInteger} N - A large safe prime
    * @param {BigInteger} A - Client's public random number
    * @param {BigInteger} v - Verifier
    * @param {BigInteger} b - Server's private random number
    * @param {BigInteger} u - Random scrambling parameter
    */
   static Ss(N: BigInteger, A: BigInteger, v: BigInteger, u: BigInteger, b: BigInteger): BigInteger {
      if (!areBigIntegers(N, A, v, b, u)) {
         throw 'invalid argument: N, A, v, b, u must be big int for Ss';
      }

      return (A.multiply(v.modPow(u, N))).modPow(b, N);
   };

   /**
    * Calculates "K" strong session key
    * @param {BigInteger} S - Session key
    * @returns {byte array}
    */
   static async K(S: BigInteger): Promise<Uint8Array> {
      if (!isBigInteger(S)) {
         throw 'invalid argument: S must be big into for K';
      }

      var Sb = bigIntegerToBytes(S, 128);
      const hash = await MGF1SHA1(Sb);
      return HashStringToByteArray(hash);
   };

   static isUint8Array(s: any): boolean {
      return s instanceof Uint8Array
   }

   /**
    * Calculates "M", client's proof of "K".
    *
    * @param {BigInteger} N - a large safe prime
    * @param {BigInteger} g - A generator modulo N
    * @param {string} username - Username, defaults to ""
    * @param {byte array} salt - User's salt
    * @param {BigInteger} A - client's public random number
    * @param {BigInteger} B - server's public random number
    * @param {byte array} k - multiplier parameter
    * @returns {hex string} SHA(SHA(N) xor SHA(g) + SHA(username) + salt + A + B + K)
    */
   static async Mc(N: BigInteger, g: BigInteger, username: string, salt: Uint8Array, A: BigInteger, B: BigInteger, K: Uint8Array): Promise<string> {
      var user = username || '';

      if (!areBigIntegers(N, g, A, B)) {
         throw 'invalid argument: not bigint';
      }
      if (!this.isUint8Array(salt) || !this.isUint8Array(K)) {
         throw 'invalid argument: not array';
      }
      if (!isString(user)) {
         throw 'invalid argument: not string';
      }

      var Nb = bigIntegerToBytes(N, 128);
      var gb = bigIntegerToBytes(g, 1);
      var shaN = await sha1(Nb);
      var shag = await sha1(gb);
      var shaUser = await sha1(user);
      var ret = HashStringToByteArray(xorHashStrings(shaN, shag));
      var shau = HashStringToByteArray(shaUser);

      var Ab = bigIntegerToBytes(A, 128);
      var Bb = bigIntegerToBytes(B, 128);
      const full_bytes = new Uint8Array([...ret, ...shau, ...salt, ...Ab, ...Bb, ...K]);
      const hash = await sha1(full_bytes);
      return hash;
   };

   /**
    * Calculates "M", server's proof of "K"
    *
    * @param {hash string} M - Client's proof of K
    * @param {BigInteger} A - Client's public random number
    * @param {byte array} K - Strong session key
    * @returns {hex string} SHA(A+M+K)
    */
   static async Ms(A: BigInteger, M: string, K: Uint8Array): Promise<string> {
      const Mary = HashStringToByteArray(M);

      if (!isBigInteger(A)) {
         throw 'invalid argument: A should be Big Integer for Ms';
      }
      if (!SRPOps.isUint8Array(Mary) || !SRPOps.isUint8Array(K)) {
         throw 'invalid argument: Mary and K should be byte array for Ms';
      }

      var Ab = bigIntegerToBytes(A, 128);

      const concatenated = new Uint8Array([...Ab, ...Mary, ...K]);

      return await sha1(concatenated);
   };

   /**
    * Calculates "V", the password verifier
    * @param {BigInteger} N - A large safe prime
    * @param {BigInteger} g - A generator modulo N
    * @param {BigInteger} x - Private key
    * @returns {BigInteger} Password verifier
    */
   static v(N: BigInteger, g: BigInteger, x: BigInteger): BigInteger {
      if (!areBigIntegers(N, g, x)) {
         throw 'invalid argument: N, g and x must be big int for v.';
      }

      return g.modPow(x, N);
   };

}

export interface ServerInfo {
   modulus: BigInteger,
   generator: BigInteger,
   salt: Uint8Array,
   publicKey: BigInteger,
   loginToken: string,
}

export interface ClientProof {
   clientPublicKey: BigInteger
   clientProof: string
 }

export class Client {
   username: string | undefined
   password: string | undefined
   serverInfo: ServerInfo | undefined
   sharedKey: Uint8Array | undefined


   setIdentity(identity: {username:string, password: string}) {
      this.username = identity.username;
      this.password = identity.password;
   }

      /**
 * Configure the client for the modulus, generator,
 * salt, and server's public key.
 *
 * @param serverInfo.modulus {BigInteger}
 * @param serverInfo.generator {BigInteger}
 * @param serverInfo.salt {Array}
 * @param serverInfo.serverPublicKey {BigInteger}
 */
   setServerInfo(serverInfo: ServerInfo) {
      if (!serverInfo.hasOwnProperty('modulus')) {
         throw 'serverInfo needs modulus';
      }
      if (!serverInfo.hasOwnProperty('generator')) {
         throw 'serverInfo needs generator';
      }
      if (!serverInfo.hasOwnProperty('salt')) {
         throw 'serverInfo needs salt';
      }
      if (!serverInfo.hasOwnProperty('publicKey')) {
         throw 'serverInfo needs publicKey';
      }
   
      this.serverInfo = serverInfo;

   }



   /**
 * Compute the client's public key (A) and proof (M)
 * from the server info.
 */
 async generatePublicKeyAndProof(): Promise<ClientProof> {
   if (!this.serverInfo || !this.username || !this.password) {
      throw 'Server Info and client identity Must Be Set First';
   }
   var N = this.serverInfo.modulus;
   var g = this.serverInfo.generator;
   var s = this.serverInfo.salt;
   var B = this.serverInfo.publicKey;

   if (B.mod(N).compareTo(BigInteger.ZERO) === 0) {
      throw 'precondition fail';
   }

   var a = await SRPOps.a();
   var A = await SRPOps.A(N, g, a);
   var u = await SRPOps.u(A, B);

   if (u.compareTo(BigInteger.ZERO) === 0) {
      throw 'precondition fail';
   }

   var k = await SRPOps.k(N, g);

   if (k.compareTo(BigInteger.ZERO) === 0) {
      throw 'precondition fail';
   }

   var x = await SRPOps.x(s, this.username, this.password);
   var S = SRPOps.Sc(N, g, B, k, x, a, u);
   var K = await SRPOps.K(S);
   var M = await SRPOps.Mc(N, g, this.username, s, A, B, K);

   this.sharedKey = K;

   return {
      clientPublicKey: A,
      clientProof: M
   };
};
}



/**
 * Create a new SRP server.
 *
 * @param lookupFunc - A function returning an object with keys n, g, v, and s.
 */
export class Server {
   lookupFunc: Function
   modulus: BigInteger
   generator: BigInteger
   salt: any
   serverPrivateKey: BigInteger
   serverPublicKey: BigInteger
   verifier: BigInteger
   sharedKey: any

   constructor(lookupFunc) {
      this.lookupFunc = lookupFunc;
   }

   /**
 * Begin a new login session.
 */
async startLogin(username: string): Promise<ServerInfo> {
   var entry = this.lookupFunc(username);

   var N = new BigInteger(byteArrayToHashString(entry.n), 16);
   var g = new BigInteger(byteArrayToHashString(entry.g), 16);
   var v = new BigInteger(byteArrayToHashString(entry.v), 16);
   var s = entry.s;
   var b = SRPOps.b();
   var B = await SRPOps.B(N, g, v, b);

   this.modulus = N;
   this.generator = g;
   this.salt = s;
   this.serverPrivateKey = b;
   this.serverPublicKey = B;
   this.verifier = v;

   return {
      modulus: this.modulus,
      generator: this.generator,
      salt: this.salt,
      publicKey: this.serverPublicKey,
      loginToken: "123"
   };
};

/**
 * Finish a login session.
 */
async finishLogin(clientParams): Promise<{serverProof: string}> {
   var N = this.modulus;
   var B = this.serverPublicKey;
   var b = this.serverPrivateKey;
   var v = this.verifier;
   var A = clientParams.clientPublicKey;
   var Mc = clientParams.clientProof;

   var u = await SRPOps.u(A, B);

   if (u.compareTo(BigInteger.ZERO) === 0) {
      throw 'precondition fail';
   }

   var S = SRPOps.Ss(N, A, v, u, b);
   var K = await SRPOps.K(S);
   var M = await SRPOps.Ms(A, Mc, K);

   this.sharedKey = K;

   return {serverProof: M};
};
}

export {BigInteger} from 'jsbn';
