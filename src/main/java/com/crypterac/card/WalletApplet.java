package com.crypterac.card;

import javacard.framework.*;
import javacard.security.*;

/**
 * The applet's main class. All incoming commands a processed by this class.
 */
public class WalletApplet extends Applet {
  static final byte INS_LOAD_KEY = (byte) 0xD0;
  static final byte INS_SIGN = (byte) 0xC0;
  static final byte INS_EXPORT_KEY = (byte) 0xC2;
  static final byte INS_SIGN_PART_TWO = (byte) 0xC1;

  private static final short EC_KEY_SIZE = 256;

  static final byte TLV_SIGNATURE_TEMPLATE = (byte) 0xA0;
  static final byte TLV_PUB_KEY = (byte) 0x80;

  private ECPublicKey publicKey;
  private ECPrivateKey privateKey;

  private Signature signature;

  /**
   * Invoked during applet installation. Creates an instance of this class. The installation parameters are passed in
   * the given buffer.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new WalletApplet(bArray, bOffset, bLength);
  }

  /**
   * Application constructor. All memory allocation is done here. The reason for this is two-fold: first the card might
   * not have Garbage Collection so dynamic allocation will eventually eat all memory. The second reason is to be sure
   * that if the application installs successfully, there is no risk of running out of memory because of other applets
   * allocating memory. The constructor also registers the applet with the JCRE so that it becomes selectable.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public WalletApplet(byte[] bArray, short bOffset, byte bLength) {
    SECP256k1.init();

    publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, EC_KEY_SIZE, false);
    privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EC_KEY_SIZE, false);

    SECP256k1.setCurveParameters(publicKey);
    SECP256k1.setCurveParameters(privateKey);

    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

    register();
  }

  /**
   * This method is called on every incoming APDU. This method is just a dispatcher which invokes the correct method
   * depending on the INS of the APDU.
   *
   * @param apdu the JCRE-owned APDU object.
   * @throws ISOException any processing error
   */
  public void process(APDU apdu) throws ISOException {
    if (selectingApplet()) {
      return;
    }

    apdu.setIncomingAndReceive();
    byte[] apduBuffer = apdu.getBuffer();

    try {
      switch (apduBuffer[ISO7816.OFFSET_INS]) {
        case INS_LOAD_KEY:
          loadKey(apdu);
          break;
        case INS_SIGN:
          sign(apdu);
          break;
        case INS_SIGN_PART_TWO:
          get_sign(apdu);
          break;
        case INS_EXPORT_KEY:
          exportKey(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
          break;
      }
    } catch(ISOException sw) {
      if (shouldRespond(apdu) && (sw.getReason() != ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED)) {
        Util.setShort(apduBuffer, (short) 0, sw.getReason());
        apdu.setOutgoingAndSend((short) 0, (short) 2);
      } else {
        throw sw;
      }
    }

    if (shouldRespond(apdu)) {
      apdu.setOutgoingAndSend((short) 0, (short) 0);
    }
  }

  private boolean shouldRespond(APDU apdu) {
    return (apdu.getCurrentState() != APDU.STATE_FULL_OUTGOING);
  }



  private void loadKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    short pubOffset = ISO7816.OFFSET_CDATA;
    short lenPub = apduBuffer[pubOffset];
    short privOffset = (short)(pubOffset + lenPub + 1);
    short lenPriv = apduBuffer[privOffset];

    JCSystem.beginTransaction();

    try {
      privateKey.setS(apduBuffer, (short) (privOffset + 1), lenPriv);
      publicKey.setW(apduBuffer, (short) (pubOffset + 1), lenPub);
    } catch (CryptoException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.commitTransaction();
  }

  private void sign(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short len = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0x00FF);

    short off = (short) (ISO7816.OFFSET_CDATA + len);

    apduBuffer[off] = TLV_SIGNATURE_TEMPLATE;
    apduBuffer[(short)(off + 3)] = TLV_PUB_KEY;
    short outLen = apduBuffer[(short)(off + 4)] = (byte) publicKey.getW(apduBuffer, (short) (off + 5));

    outLen += 5;
    short sigOff = (short) (off + outLen);
    signature.init(privateKey, Signature.MODE_SIGN);
    outLen += signature.signPreComputedHash(apduBuffer, ISO7816.OFFSET_CDATA, len, apduBuffer, sigOff);

    outLen += Crypto.fixS(apduBuffer, sigOff);

    apduBuffer[(short)(off + 1)] = (byte) 0x81;
    apduBuffer[(short)(off + 2)] = (byte) (outLen - 3);

    apdu.setOutgoingAndSend(off, outLen);
  }

  private void sign_two(APDU apdu) {
    
  }


  private void exportKey(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    short len = publicKey.getW(apduBuffer, (short) 0);

    apdu.setOutgoingAndSend((short) 0, len);
  }
}
