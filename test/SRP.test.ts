/**
 * @file SRP library tests
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */

'use strict';
import { Client, Server, SRPOps, UserEntry } from '../lib/SRP';
import { describe, it, assert } from 'vitest';
import {
   b64tohex,
   hexStringToBase64,
   xorHashStrings,
   HashStringToByteArray,
} from '../lib/Utils';
import { byteArrayToBase64 } from '../lib/Base64';
import { bigIntFromBase64, bigIntToBase64 } from '../lib/BigInt';

// fake database
const srpDatabase: { [key: string]: UserEntry } = {
   pantsman: {
      user: 'pantsman',
      password: '',
      n: new Uint8Array([
         0x88, 0x95, 0x90, 0xff, 0x13, 0x4b, 0x81, 0xa4, 0x0c, 0xf0, 0x0d, 0xd7,
         0x81, 0x0e, 0x23, 0x9a, 0xbe, 0x32, 0x3b, 0x0e, 0x04, 0x43, 0xca, 0x5c,
         0x8d, 0x0d, 0xa9, 0x24, 0x43, 0x68, 0xb9, 0x8f, 0x4a, 0x7c, 0xce, 0x64,
         0x8c, 0xe1, 0x89, 0x76, 0x23, 0x8b, 0x9d, 0x56, 0x19, 0xab, 0x30, 0xcc,
         0xe9, 0xb9, 0x3b, 0xc0, 0x85, 0x42, 0x06, 0x83, 0xbc, 0xf3, 0x77, 0x67,
         0x5a, 0x8e, 0x22, 0x5d, 0x5b, 0xe3, 0xb0, 0xfd, 0x44, 0x3d, 0x9f, 0x1f,
         0xb3, 0xd0, 0xf6, 0xfe, 0xed, 0x5b, 0x5e, 0xd7, 0xdc, 0xab, 0xbf, 0x99,
         0x5a, 0x0b, 0xd6, 0x18, 0x09, 0x9a, 0x8a, 0xff, 0x64, 0xd9, 0x20, 0x14,
         0xf2, 0xda, 0xb8, 0x5b, 0x87, 0xed, 0xb1, 0xe3, 0x20, 0xf8, 0x20, 0xf5,
         0xaa, 0xda, 0x46, 0x5f, 0x29, 0x48, 0xc6, 0x35, 0xa2, 0x47, 0x81, 0xad,
         0x79, 0x97, 0x60, 0x6c, 0x50, 0x12, 0xf0, 0xc7,
      ]),
      g: new Uint8Array([0x05]),
      s: new Uint8Array([
         0x52, 0xee, 0xc1, 0x8f, 0xb9, 0xa0, 0xab, 0x55, 0x5e, 0xe4, 0xb3, 0x86,
         0xee, 0xb4, 0xa3, 0x94,
      ]),
      v: new Uint8Array([
         0x27, 0xd8, 0xbc, 0x25, 0x09, 0x19, 0xf7, 0x4d, 0x43, 0x8f, 0xa5, 0xd4,
         0x9a, 0xeb, 0xca, 0xe7, 0x70, 0xb5, 0xff, 0xda, 0x67, 0xbb, 0xb5, 0x83,
         0xaa, 0x14, 0x2b, 0x49, 0x95, 0xf5, 0x1d, 0x0c, 0x11, 0x7d, 0xa9, 0xe1,
         0xdb, 0xd9, 0xee, 0xd1, 0x0c, 0x66, 0xa3, 0xf1, 0x07, 0x42, 0x2a, 0x5e,
         0xf3, 0xe1, 0xa1, 0xc6, 0x19, 0xe7, 0x73, 0x0f, 0xaf, 0x7f, 0x77, 0x26,
         0xa9, 0x53, 0xc3, 0xed, 0x5f, 0x28, 0x42, 0x7e, 0x47, 0x9e, 0xa5, 0x64,
         0x52, 0x74, 0xbe, 0x99, 0x97, 0xd2, 0x33, 0x80, 0x92, 0x36, 0xce, 0x57,
         0x1d, 0xb9, 0xd6, 0xd4, 0x7b, 0x82, 0xc4, 0xa4, 0xd1, 0xd3, 0xe6, 0xf9,
         0x2e, 0x8b, 0x9b, 0x32, 0x89, 0x67, 0x55, 0x6d, 0x90, 0x3a, 0xcd, 0xba,
         0x1e, 0x27, 0x3c, 0x9b, 0x69, 0x35, 0xf7, 0x2e, 0x1d, 0x2a, 0x4a, 0x0f,
         0xf9, 0xc9, 0x26, 0x9e, 0x05, 0xd0, 0xf2, 0xae,
      ]),
   },
   brandon: {
      user: 'brandon',
      password: 'test',
      n: new Uint8Array([
         0x88, 0x95, 0x90, 0xff, 0x13, 0x4b, 0x81, 0xa4, 0x0c, 0xf0, 0x0d, 0xd7,
         0x81, 0x0e, 0x23, 0x9a, 0xbe, 0x32, 0x3b, 0x0e, 0x04, 0x43, 0xca, 0x5c,
         0x8d, 0x0d, 0xa9, 0x24, 0x43, 0x68, 0xb9, 0x8f, 0x4a, 0x7c, 0xce, 0x64,
         0x8c, 0xe1, 0x89, 0x76, 0x23, 0x8b, 0x9d, 0x56, 0x19, 0xab, 0x30, 0xcc,
         0xe9, 0xb9, 0x3b, 0xc0, 0x85, 0x42, 0x06, 0x83, 0xbc, 0xf3, 0x77, 0x67,
         0x5a, 0x8e, 0x22, 0x5d, 0x5b, 0xe3, 0xb0, 0xfd, 0x44, 0x3d, 0x9f, 0x1f,
         0xb3, 0xd0, 0xf6, 0xfe, 0xed, 0x5b, 0x5e, 0xd7, 0xdc, 0xab, 0xbf, 0x99,
         0x5a, 0x0b, 0xd6, 0x18, 0x09, 0x9a, 0x8a, 0xff, 0x64, 0xd9, 0x20, 0x14,
         0xf2, 0xda, 0xb8, 0x5b, 0x87, 0xed, 0xb1, 0xe3, 0x20, 0xf8, 0x20, 0xf5,
         0xaa, 0xda, 0x46, 0x5f, 0x29, 0x48, 0xc6, 0x35, 0xa2, 0x47, 0x81, 0xad,
         0x79, 0x97, 0x60, 0x6c, 0x50, 0x12, 0xf0, 0xc7,
      ]),
      g: new Uint8Array([0x05]),
      s: new Uint8Array([
         0x90, 0x17, 0xb7, 0x0b, 0x4b, 0xfc, 0x42, 0x47, 0xfc, 0xa0, 0x68, 0x7e,
         0x68, 0xf7, 0x2c, 0x63,
      ]),
      v: new Uint8Array([
         0x83, 0xa9, 0xd2, 0xdd, 0xfe, 0x65, 0x71, 0xf8, 0x29, 0xe4, 0xb0, 0xf8,
         0x44, 0xc3, 0xe6, 0x4c, 0x73, 0xdb, 0x32, 0xb1, 0xb7, 0x0f, 0x45, 0x9b,
         0xad, 0x99, 0xc6, 0xeb, 0xa2, 0x8e, 0x45, 0x61, 0xff, 0x79, 0x7f, 0x6a,
         0xfa, 0xe4, 0x11, 0xff, 0x1e, 0xa8, 0xfb, 0x64, 0x7e, 0xe6, 0x86, 0xdc,
         0x52, 0x0d, 0xff, 0xea, 0x2f, 0xd9, 0x12, 0xee, 0xeb, 0xb5, 0xdc, 0xf3,
         0x13, 0x6b, 0xa6, 0xbc, 0xb1, 0x2c, 0x14, 0xd5, 0x54, 0x07, 0x57, 0xd4,
         0x22, 0x44, 0x6f, 0x7e, 0x16, 0xe2, 0x58, 0xe4, 0x19, 0x52, 0x7a, 0x85,
         0xb9, 0x58, 0x78, 0xd9, 0xbb, 0x16, 0xbf, 0x55, 0xbe, 0x34, 0x99, 0x91,
         0xb8, 0x59, 0x0e, 0x16, 0x08, 0xd4, 0xb0, 0x22, 0xeb, 0xe8, 0xb4, 0xa6,
         0xd2, 0x32, 0x0f, 0x37, 0x14, 0xd8, 0x0f, 0x5c, 0xb7, 0x71, 0xa9, 0xa4,
         0x3d, 0x58, 0xa8, 0xf1, 0x51, 0x66, 0x0d, 0x3e,
      ]),
   },
};

describe('SRP', function () {
   it('should have a mutually-intelligible Client and Server', async function () {
      const username = 'brandon';
      const password = 'test';

      const client = new Client();
      const server = new Server(function (username) {
         // needs to return n, g, v, and s
         //
         return srpDatabase[username];
      });

      const loginInfo = await server.startLogin(username);

      client.setIdentity({ username: username, password: password });
      client.setServerInfo(loginInfo);
      const clientParams = await client.generatePublicKeyAndProof();
      await server.finishLogin(clientParams);

      assert.deepEqual(client.sharedKey, server.sharedKey);
   });

   it('can xor hash strings correctly', function () {
      const str1 = '6310e7f959b8d6cb58505a80e7115b2e77502c8e';
      const str2 = '24d65375092b75cb05060f1561c8b079839a3fda';
      const expected = '47c6b48c5093a3005d56559586d9eb57f4ca1354';

      assert.deepEqual(xorHashStrings(str1, str2), expected);
   });

   it('should match results step-by-step', async () => {
      // A bunch of magic values, copied from the C# (Silverlight) implementation.
      // This is to make sure that we're doing math the same way.

      // These are the "input" values, returned by the server.
      const Nenc =
         'ieJUvpnjDnS8CjQLseVMV6+bLPH2bNQLFVj1nVgSrCdErkLGUGhosubcgk6I7XoqM417RFquVMZvqgXMwggvoJyvy003qXK1bukOLlW1cRW6KLCzRBljPsMG6WeNbKqAatVX1MDHtc/d35B4q2ZJ/UXDzFCE2H/MbbJH7yylr2c=';
      const genc = 'Cw==';
      const salt = 'K7YIn92KQeT9NfyZx7AYjw==';
      const Benc =
         'MUOOiUox8LapdLRLlnBVhd1SK9a1324WdBUtrfzBYAySSo1LgEhtZOQlogbTBGPgfsFcyiH1uo/WcWSRzMyg27wfryZIKpEcENAZXly+3Wzy1rTSo8ZY4x9EwcK9HjV+TQxN5uvJ+zCcz/yxO5oLSSdKY7KLvvGtX7LVdENcEeE=';
      const username = 'JohnDoe';
      const password = 'secret';

      // For this test, we don't use SRP.a() to generate a random number.
      const aenc =
         'eCUSboAbAdL0ZMy4zGq7CmulHcC94mVWD8GRy1HbfZg4MOuDQWYOio2H9Lfr27tCuHG5BSgZZudy1XX8SVm4hOvDZKNeQBcplWwadPmHjxyFHEByR5XbReJ+cLT5K7n/YdIwoJSwYj81HQYoOFjwKukKYQvh5zStm0EDAXZvdfg=';

      // These are the expected outputs.
      const Aenc =
         'bCRv5uIvBUyDZ7owIXxC9hCPUwK9/wndbcypk2Qnc5wiak5KSpe0eE6Mi/1PweqE9mu8WbpkHrVjiXUKNsPeyS9IkxieMKfsHw7WRTlSnsgFVInSo/UlKTDqP8gPxbgo9l/f6T9798z/uTeO+yk/ABHbPOPJamF/b+HWUKjSATk=';
      const uenc = 'TY5+GM9i+WIqiTh7QDCcnYPJbE0=';
      const kenc = 'B64MpqqSRGUVRn0f3LdsfHJYMMw=';
      const xenc = 'psfVoz95IZaeVyUg5tAZSZdJTNU=';
      const Senc =
         'H9jbD04W810duG5/yFeSw2mW81wKTZ4g3QE5VDZRa/nG+QZ//I2cVHFn6r8z1oWuBm6lf3d/Ade2qWV4xeqyEjiAJjCO9gcvqS/d4k0Tv9UBiGPx9JA16HTaUO3C5ixFY3qQ3+Uf25jXHvuSfMsPIS6cQUtfQBRN8/r6wqNBG9c=';
      const Kenc = '86sYQyRFKP7A0lZWYHh13/3ZuMQaghRBnH+jDhvAO9pb6ToWBueFhw==';
      const Mcenc = '7+gitq19/I//F43+6gnRgQrtfmU=';
      const Msenc = 'keoskY9NXrDYAZ2h3QCY2TTs5mM=';

      const N = bigIntFromBase64(Nenc);
      const g = bigIntFromBase64(genc);
      const s = HashStringToByteArray(b64tohex(salt));
      const B = bigIntFromBase64(Benc);
      const a = bigIntFromBase64(aenc);

      // And now, the math!

      const A = SRPOps.A(N, g, a);
      const AencActual = bigIntToBase64(A, 128);
      assert.deepEqual(AencActual, Aenc);

      const u = await SRPOps.u(A, B);
      const uencActual = bigIntToBase64(u, 20);
      assert.deepEqual(uencActual, uenc);

      const k = await SRPOps.k(N, g);
      const kencActual = bigIntToBase64(k, 20);
      assert.deepEqual(kencActual, kenc);

      const x = await SRPOps.x(s, username, password);
      const xencActual = bigIntToBase64(x, 20);
      assert.deepEqual(xencActual, xenc);

      const S = SRPOps.Sc(N, g, B, k, x, a, u);
      const SencActual = bigIntToBase64(S, 128);
      assert.deepEqual(SencActual, Senc);

      const K = await SRPOps.K(S);
      const KencActual = byteArrayToBase64(K);
      assert.deepEqual(KencActual, Kenc);

      const Mc = await SRPOps.Mc(N, g, username, s, A, B, K);
      const McencActual = hexStringToBase64(Mc);
      assert.deepEqual(McencActual, Mcenc);

      const Ms = await SRPOps.Ms(A, Mc, K);
      const MsencActual = hexStringToBase64(Ms);
      assert.deepEqual(MsencActual, Msenc);
   });
});
