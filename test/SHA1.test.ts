/**
 * @file sha1 library tests
 * @copyright National Instruments, 2016-2017
 * @license MIT
 */

'use strict';
import { sha1 } from '../lib/SHA1';
import { describe, it, assert } from 'vitest';

describe('SHA1', function () {
   it('should handle arrays of bytes', async function () {
      const message = new Uint8Array([0x61, 0x62, 0x63]);
      assert.equal(
         'a9993e364706816aba3e25717850c26c9cd0d89d',
         await sha1(message),
      );
   });

   // somewhat important: jsbn BigInteger.toByteArray returns int8 values,
   // not uint8 values... the hash function needs to cope.
   it('should handle negative values', async function () {
      const test1a = new Uint8Array([0, 0, 0, 0, 0xff]);
      const test1b = new Uint8Array([0, 0, 0, 0, -1]);
      const test2a = new Uint8Array([0, 0, 0, 0xff, 0]);
      const test2b = new Uint8Array([0, 0, 0, -1, 0]);
      const test3a = new Uint8Array([0, 0, 0xff, 0, 0]);
      const test3b = new Uint8Array([0, 0, -1, 0, 0]);
      const test4a = new Uint8Array([0, 0xff, 0, 0, 0]);
      const test4b = new Uint8Array([0, -1, 0, 0, 0]);
      const test5a = new Uint8Array([0xff, 0, 0, 0, 0]);
      const test5b = new Uint8Array([-1, 0, 0, 0, 0]);

      const expected1 = '836adc5637c4320983016c50c1c3625f9f92ce1a';
      const expected2 = '2da1eb63c05691a88dce231f0279cb84696901dc';
      const expected3 = '4d86dc9985d62b84d6199b4d58a838e21507077a';
      const expected4 = '645375a94b9cdd65472be4abc0d52626c0cc70e4';
      const expected5 = '88f3c8e6e819aa83da1ce48353b2bddaad759fb9';

      assert.equal(await sha1(test1a), expected1);
      assert.equal(await sha1(test1b), expected1);
      assert.equal(await sha1(test2a), expected2);
      assert.equal(await sha1(test2b), expected2);
      assert.equal(await sha1(test3a), expected3);
      assert.equal(await sha1(test3b), expected3);
      assert.equal(await sha1(test4a), expected4);
      assert.equal(await sha1(test4b), expected4);
      assert.equal(await sha1(test5a), expected5);
      assert.equal(await sha1(test5b), expected5);
   });
});
