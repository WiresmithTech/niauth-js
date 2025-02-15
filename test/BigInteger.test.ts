/**
 * @file biginteger library tests
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */

'use strict';
import { BigInteger } from 'jsbn';
import { describe, it, assert } from 'vitest';

describe('BigInteger', function () {
   function _byteArrayToHexString(ar) {
      let hs = '';
      for (let i = 0; i < ar.length; ++i) {
         hs += ('00' + (ar[i] & 0xff).toString(16)).substr(-2);
      }
      return hs;
   }

   function factorial(n) {
      let sum = new BigInteger('1', 10);

      for (let i = 1; i < n; ++i) {
         let iBig = new BigInteger(i.toString(), 10);
         iBig = iBig.multiply(sum);
         sum = sum.add(iBig);
      }

      return sum;
   }

   // This is to ensure that when we convert a BigInteger type to a byte stream,
   // the bytes we get back are what we expect to get.
   it('should have a defined byte sequence for 47!', function () {
      const expected = [
         0x29, 0x33, 0x78, 0xa1, 0x1e, 0xe6, 0x48, 0x22, 0x16, 0x7f, 0x74, 0x17,
         0xfd, 0xd3, 0xa5, 0x0e, 0xc0, 0xee, 0x4f, 0x74, 0x00, 0x00, 0x00, 0x00,
         0x00,
      ];

      const actual = factorial(47);

      assert.equal(
         actual.toString(),
         '258623241511168180642964355153611979969197632389120000000000',
      );

      const ebi = new BigInteger(_byteArrayToHexString(expected), 16);
      const abi = new BigInteger(_byteArrayToHexString(actual.toByteArray()), 16);

      assert.equal(abi.toString(), ebi.toString());
   });
});
