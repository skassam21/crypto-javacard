package com.crypterac.card;

import javacard.framework.Util;

/**
 * Crypto utilities, mostly BIP32 related. The init method must be called during application installation. This class
 * is not meant to be instantiated.
 */
public class Crypto {
  final static private byte[] MAX_S = { (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x5D, (byte) 0x57, (byte) 0x6E, (byte) 0x73, (byte) 0x57, (byte) 0xA4, (byte) 0x50, (byte) 0x1D, (byte) 0xDF, (byte) 0xE9, (byte) 0x2F, (byte) 0x46, (byte) 0x68, (byte) 0x1B, (byte) 0x20, (byte) 0xA0 };
  final static private byte[] S_SUB = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B, (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41 };

  /**
   * Fixes the S value of the signature as described in BIP-62 to avoid malleable signatures. It also fixes the all
   * internal TLV length fields. Returns the number of bytes by which the overall signature length changed (0 or -1).
   *
   * @param sig the signature
   * @param off the offset
   * @return the number of bytes by which the signature length changed
   */
  static short fixS(byte[] sig, short off) {
    short sOff = (short) (sig[(short) (off + 3)] + (short) (off + 5));
    short ret = 0;

    if (sig[sOff] == 33) {
      Util.arrayCopyNonAtomic(sig, (short) (sOff + 2), sig, (short) (sOff + 1), (short) 32);
      sig[sOff] = 32;
      sig[(short)(off + 1)]--;
      ret = -1;
    }

    sOff++;

    if (ret == -1 || ucmp256(sig, sOff, MAX_S, (short) 0) > 0) {
      sub256(S_SUB, (short) 0, sig, sOff, sig, sOff);
    }

    return ret;
  }

  /**
   * Modulo addition of two 256-bit numbers.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @param n the modulo
   * @param nOff the offset of the modulo
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   */
  private static void addm256(byte[] a, short aOff, byte[] b, short bOff, byte[] n, short nOff, byte[] out, short outOff) {
    if ((add256(a, aOff, b, bOff, out, outOff) != 0) || (ucmp256(out, outOff, n, nOff) > 0)) {
      sub256(out, outOff, n, nOff, out, outOff);
    }
  }

  /**
   * Compares two 256-bit numbers. Returns a positive number if a > b, a negative one if a < b and 0 if a = b.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @return the comparison result
   */
  private static short ucmp256(byte[] a, short aOff, byte[] b, short bOff) {
    short ai, bi;
    for (short i = 0 ; i < 32; i++) {
      ai = (short)(a[(short)(aOff + i)] & 0x00ff);
      bi = (short)(b[(short)(bOff + i)] & 0x00ff);

      if (ai != bi) {
        return (short)(ai - bi);
      }
    }

    return 0;
  }

  /**
   * Checks if the given 256-bit number is 0.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @return true if a is 0, false otherwise
   */
  private static boolean isZero256(byte[] a, short aOff) {
    boolean isZero = true;

    for (short i = 0; i < (byte) 32; i++) {
      if (a[(short)(aOff + i)] != 0) {
        isZero = false;
        break;
      }
    }

    return isZero;
  }

  /**
   * Addition of two 256-bit numbers.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the carry of the addition
   */
  private static short add256(byte[] a, short aOff,  byte[] b, short bOff, byte[] out, short outOff) {
    short outI = 0;
    for (short i = 31 ; i >= 0 ; i--) {
      outI = (short) ((short)(a[(short)(aOff + i)] & 0xFF) + (short)(b[(short)(bOff + i)] & 0xFF) + outI);
      out[(short)(outOff + i)] = (byte)outI ;
      outI = (short)(outI >> 8);
    }
    return outI;
  }

  /**
   * Subtraction of two 256-bit numbers.
   *
   * @param a the a operand
   * @param aOff the offset of the a operand
   * @param b the b operand
   * @param bOff the offset of the b operand
   * @param out the output buffer
   * @param outOff the offset in the output buffer
   * @return the carry of the subtraction
   */
  private static short sub256(byte[] a, short aOff,  byte[] b, short bOff, byte[] out, short outOff) {
    short outI = 0;

    for (short i = 31 ; i >= 0 ; i--) {
      outI = (short)  ((short)(a[(short)(aOff + i)] & 0xFF) - (short)(b[(short)(bOff + i)] & 0xFF) - outI);
      out[(short)(outOff + i)] = (byte)outI ;
      outI = (short)(((outI >> 8) != 0) ? 1 : 0);
    }

    return outI;
  }
}
