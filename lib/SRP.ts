/**
 * @file SRP implementation
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */
'use strict';
import { modAdd, modMultiply, modPow } from 'bigint-mod-arith';
import { sha1 } from './SHA1';
import {
   HashStringToByteArray,
   xorHashStrings,
} from './Utils.ts';
import { bigIntFromByteArray, bigIntFromHex, randomBigInt, bigIntegerToBytes } from './BigInt.ts';

const isbigint = function (x) {
   return typeof x === 'bigint';
};

const arebigints = function (...numbers: bigint[]) {
   for (let i = 0; i < numbers.length; ++i) {
      if (!isbigint(numbers[i])) {
         return false;
      }
   }
   return true;
};

const isString = function (x) {
   return typeof x === 'string';
};

/*
 * MGF1 mask generation function with SHA1 hash.
 */
async function MGF1SHA1(byteArray: Uint8Array): Promise<string> {
   const C1 = new Uint8Array([...byteArray, 0, 0, 0, 0]);
   const C2 = new Uint8Array([...byteArray, 0, 0, 0, 1]);
   return (await sha1(C1)) + (await sha1(C2));
}

/**
 * SRP mathematical operations.
 *
 * Style note: These functions use a lot of single-character function and
 * constiable names. This harkens back to the original Secure Remote Password
 * protocol paper. See http://srp.stanford.edu/ndss.html
 */
export class SRPOps {
   /**
    * Returns client's random number.
    * @returns {bigint}
    */
   static a(): bigint {
      return randomBigInt(512);
   }

   static b(): bigint {
      return randomBigInt(512);
   }

   /*
    * Calculates "A", public random number.
    * @param {bigint} N - A large safe prime
    * @param {bigint} g - A generator modulo N
    * @param {bigint} a - A random number
    * @returns {bigint} g^a % N
    */
   static A(N: bigint, g: bigint, a: bigint): bigint {
      if (!arebigints(N, g, a)) {
         throw 'invalid argument: N, g and a should be big int for A';
      }
      return modPow(g, a, N);
   }

   /**
    * Calculates "B", public random number.
    * @param {bigint} N - A large safe prime
    * @param {bigint} g - A generator modulo N
    * @param {bigint} v - Password verifier
    * @param {bigint} b - A random number
    * @returns {bigint} k * v + g^b
    */
   static async B(
      N: bigint,
      g: bigint,
      v: bigint,
      b: bigint,
   ): Promise<bigint> {
      let k = await SRPOps.k(N, g);
      const mod_pow = modPow(g, b, N);
      const kv = k * v;
      return modAdd([kv, mod_pow], N);
   }

   /**
    * Calculates "u" random scrambling parameter.
    * u = SHA(A+B)
    * @param {bigint} A - Client public random number
    * @param {bigint} B - Client public random number
    * @returns {bigint} SHA(A+B)
    */
   static async u(A: bigint, B: bigint): Promise<bigint> {
      if (!arebigints(A, B)) {
         return Promise.reject(
            'invalid argument: A and B must be big int for u',
         );
      }

      const Ab = bigIntegerToBytes(A, 128);
      const Bb = bigIntegerToBytes(B, 128);
      const ABb = new Uint8Array([...Ab, ...Bb]);
      const aBbSha = await sha1(ABb);
      return bigIntFromHex(aBbSha);
   }

   /**
    * Calculates "k" multiplier number
    * k = SHA(N + PAD(g))
    * @param {bigint} N - A large safe prime
    * @param {bigint} g - a generator modulo N
    * @returns {bigint} SHA(N+PAD(g))
    */
   static async k(N: bigint, g: bigint): Promise<bigint> {
      if (!arebigints(N, g)) {
         return Promise.reject(
            'invalid argument: N and g must be big int for k.',
         );
      }

      const Nb = bigIntegerToBytes(N, 128);
      const gb = bigIntegerToBytes(g, 128);
      const Ngb = new Uint8Array([...Nb, ...gb]);
      const NgbSha = await sha1(Ngb);
      const k = bigIntFromHex(NgbSha);
      return bigIntFromHex(NgbSha);
   }

   /**
    * Calculates the value of "x" private key derived from username,
    * password, and salt.
    * x = SHA(salt + SHA(username + ":" + assword))
    * @param {byte array} salt User's salt
    * @param {string} username User's name
    * @param {string} password User's password
    * returns {bigint} SHA(salt + SHA(username + ":" + password))
    */
   static async x(
      salt: Uint8Array,
      username: string,
      password: string,
   ): Promise<bigint> {
      const user = username || '';
      const pass = password || '';

      if (!SRPOps.isUint8Array(salt)) {
         return Promise.reject(
            'invalid argument: salt must be byte array for x',
         );
      }
      if (!isString(user) || !isString(pass)) {
         return Promise.reject(
            'invalid argument: User and password must be string for x',
         );
      }

      const concat1 = user + ':' + pass;
      const concat1Sha = await sha1(concat1);
      const concat1ShaBytes = HashStringToByteArray(concat1Sha);
      const concat2 = new Uint8Array([...salt, ...concat1ShaBytes]);
      const concat2Sha = await sha1(concat2);
      return bigIntFromHex(concat2Sha);
   }

   /**
    * Calculates the client side value of "S".
    * @param {bigint} N - A large safe prime
    * @param {bigint} g - A generator modulo N
    * @param {bigint} B - Server's public random number
    * @param {bigint} k - Multiplier parameter
    * @param {bigint} x - Private key
    * @param {bigint} a - Client's private random number
    * @param {bigint} u - Random scrambling parameter
    * @returns {bigint} (B - g^x) ^ (a + u * x) % N
    */
   static Sc(
      N: bigint,
      g: bigint,
      B: bigint,
      k: bigint,
      x: bigint,
      a: bigint,
      u: bigint,
   ): bigint {
      if (!arebigints(N, g, B, k, x, a, u)) {
         throw 'invalid argument: N, g, B, k, x, a, u bust be big ints for Sc';
      }

      const g_modpow_x_n = modPow(g, x, N);
      const n_sub_g_modpow_x = N - g_modpow_x_n;
      const b_prime = B + modMultiply([k, n_sub_g_modpow_x], N);
      return modPow(b_prime, a + (u * x), N);
   }

   /**
    * Calculates the server side value of "S"
    * @param {bigint} N - A large safe prime
    * @param {bigint} A - Client's public random number
    * @param {bigint} v - Verifier
    * @param {bigint} b - Server's private random number
    * @param {bigint} u - Random scrambling parameter
    */
   static Ss(
      N: bigint,
      A: bigint,
      v: bigint,
      u: bigint,
      b: bigint,
   ): bigint {
      if (!arebigints(N, A, v, b, u)) {
         throw 'invalid argument: N, A, v, b, u must be big int for Ss';
      }

      const v_modpow_u_n = modPow(v, u, N);
      return modPow(A * v_modpow_u_n, b, N);
   }

   /**
    * Calculates "K" strong session key
    * @param {bigint} S - Session key
    * @returns {byte array}
    */
   static async K(S: bigint): Promise<Uint8Array> {
      if (!isbigint(S)) {
         return Promise.reject('invalid argument: S must be big int for K');
      }

      const Sb = bigIntegerToBytes(S, 128);
      const hash = await MGF1SHA1(Sb);
      return HashStringToByteArray(hash);
   }

   static isUint8Array(s: any): boolean {
      return s instanceof Uint8Array;
   }

   /**
    * Calculates "M", client's proof of "K".
    *
    * @param {bigint} N - a large safe prime
    * @param {bigint} g - A generator modulo N
    * @param {string} username - Username, defaults to ""
    * @param {byte array} salt - User's salt
    * @param {bigint} A - client's public random number
    * @param {bigint} B - server's public random number
    * @param {byte array} k - multiplier parameter
    * @returns {hex string} SHA(SHA(N) xor SHA(g) + SHA(username) + salt + A + B + K)
    */
   static async Mc(
      N: bigint,
      g: bigint,
      username: string,
      salt: Uint8Array,
      A: bigint,
      B: bigint,
      K: Uint8Array,
   ): Promise<string> {
      const user = username || '';

      if (!arebigints(N, g, A, B)) {
         return Promise.reject('Invalid argument. Bigint missing for Mc');
      }
      if (!this.isUint8Array(salt) || !this.isUint8Array(K)) {
         return Promise.reject('salt or k not an array for Mc.');
      }
      if (!isString(user)) {
         return Promise.reject('user is not a string for mc.');
      }

      const Nb = bigIntegerToBytes(N, 128);
      const gb = bigIntegerToBytes(g, 1);
      const shaN = await sha1(Nb);
      const shag = await sha1(gb);
      const shaUser = await sha1(user);
      const ret = HashStringToByteArray(xorHashStrings(shaN, shag));
      const shau = HashStringToByteArray(shaUser);

      const Ab = bigIntegerToBytes(A, 128);
      const Bb = bigIntegerToBytes(B, 128);
      const fullBytes = new Uint8Array([
         ...ret,
         ...shau,
         ...salt,
         ...Ab,
         ...Bb,
         ...K,
      ]);
      const hash = await sha1(fullBytes);
      return hash;
   }

   /**
    * Calculates "M", server's proof of "K"
    *
    * @param {hash string} M - Client's proof of K
    * @param {bigint} A - Client's public random number
    * @param {byte array} K - Strong session key
    * @returns {hex string} SHA(A+M+K)
    */
   static async Ms(A: bigint, M: string, K: Uint8Array): Promise<string> {
      const Mary = HashStringToByteArray(M);

      if (!isbigint(A)) {
         return Promise.reject(
            'invalid argument: A should be Big Integer for Ms',
         );
      }
      if (!SRPOps.isUint8Array(Mary) || !SRPOps.isUint8Array(K)) {
         return Promise.reject(
            'invalid argument: Mary and K should be byte array for Ms',
         );
      }

      const Ab = bigIntegerToBytes(A, 128);

      const concatenated = new Uint8Array([...Ab, ...Mary, ...K]);

      return await sha1(concatenated);
   }

   /**
    * Calculates "V", the password verifier
    * @param {bigint} N - A large safe prime
    * @param {bigint} g - A generator modulo N
    * @param {bigint} x - Private key
    * @returns {bigint} Password verifier
    */
   static v(N: bigint, g: bigint, x: bigint): bigint {
      if (!arebigints(N, g, x)) {
         throw 'invalid argument: N, g and x must be big int for v.';
      }

      return modPow(g, x, N);
   }
}

export interface ServerInfo {
   modulus: bigint;
   generator: bigint;
   salt: Uint8Array;
   publicKey: bigint;
   loginToken: string;
}

export interface ClientProof {
   clientPublicKey: bigint;
   clientProof: string;
}

interface Identity {
   username: string;
   password: string;
}

export class Client {
   identity: Identity | undefined;
   serverInfo: ServerInfo | undefined;
   sharedKey: Uint8Array | undefined;

   setIdentity(identity: { username: string; password: string }) {
      this.identity = identity;
   }

   /**
    * Configure the client for the modulus, generator,
    * salt, and server's public key.
    *
    * @param serverInfo.modulus {bigint}
    * @param serverInfo.generator {bigint}
    * @param serverInfo.salt {Array}
    * @param serverInfo.serverPublicKey {bigint}
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
      if (!this.serverInfo || !this.identity) {
         throw 'Server Info and client identity Must Be Set First';
      }
      const N = this.serverInfo.modulus;
      const g = this.serverInfo.generator;
      const s = this.serverInfo.salt;
      const B = this.serverInfo.publicKey;

      if (modAdd([B], N) === 0n) {
         throw 'precondition fail';
      }

      const a = await SRPOps.a();
      const A = await SRPOps.A(N, g, a);
      const u = await SRPOps.u(A, B);

      if (u === 0n) {
         throw 'precondition fail';
      }

      const k = await SRPOps.k(N, g);

      if (k === 0n) {
         throw 'precondition fail';
      }

      const x = await SRPOps.x(s, this.identity.username, this.identity.password);
      const S = SRPOps.Sc(N, g, B, k, x, a, u);
      const K = await SRPOps.K(S);
      const M = await SRPOps.Mc(N, g, this.identity.username, s, A, B, K);

      this.sharedKey = K;

      return {
         clientPublicKey: A,
         clientProof: M,
      };
   }
}

export type UserEntry = {
   user: string,
   password: string,
   n: Uint8Array,
   g: Uint8Array,
   v: Uint8Array,
   s: Uint8Array,
}

/**
 * Create a new SRP server.
 *
 * @param lookupFunc - A function returning an object with keys n, g, v, and s.
 */
export class Server {
   lookupFunc: (username: string) => UserEntry;
   modulus: bigint;
   generator: bigint;
   salt: any;
   serverPrivateKey: bigint;
   serverPublicKey: bigint;
   verifier: bigint;
   sharedKey: any;

   constructor(lookupFunc) {
      this.lookupFunc = lookupFunc;
   }

   /**
    * Begin a new login session.
    */
   async startLogin(username: string): Promise<ServerInfo> {
      const entry = this.lookupFunc(username);

      const N = bigIntFromByteArray(entry.n);
      const g = bigIntFromByteArray(entry.g);
      const v = bigIntFromByteArray(entry.v);
      const s = entry.s;
      const b = SRPOps.b();
      const B = await SRPOps.B(N, g, v, b);

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
         loginToken: '123',
      };
   }

   /**
    * Finish a login session.
    */
   async finishLogin(clientParams): Promise<{ serverProof: string }> {
      const N = this.modulus;
      const B = this.serverPublicKey;
      const b = this.serverPrivateKey;
      const v = this.verifier;
      const A = clientParams.clientPublicKey;
      const Mc = clientParams.clientProof;

      const u = await SRPOps.u(A, B);

      if (u === 0n) {
         throw 'precondition fail';
      }

      const S = SRPOps.Ss(N, A, v, u, b);
      const K = await SRPOps.K(S);
      const M = await SRPOps.Ms(A, Mc, K);

      this.sharedKey = K;

      return { serverProof: M };
   }
}

