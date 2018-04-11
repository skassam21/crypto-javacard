package com.crypterac.card;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import lombok.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.*;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.RawTransaction;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import javax.smartcardio.*;
import javax.ws.rs.Produces;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;


import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;


import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("Test the Wallet Applet")
public class WalletAppletTest {
  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;
  private static CardSimulator simulator;

  private WalletAppletCommandSet cmdSet;

  private static final boolean USE_SIMULATOR;

  private static final String TEST_PRIVATE_KEY = "0x39dcc25d04babcf9cc6fa1b1a217208b464fd9946710d4fd1c6e829aa8143f2a";

  static {
    USE_SIMULATOR = !System.getProperty("com.crypterac.card.test.simulated", "false").equals("false");
    if (USE_SIMULATOR) {
      System.out.println("Testing on the simulator\n");
    } else {
      System.out.println("Testing on the card\n");
    }
  }

  @BeforeAll
  static void initAll() throws CardException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    if (USE_SIMULATOR) {
      simulator = new CardSimulator();
      AID appletAID = AIDUtil.create(WalletAppletCommandSet.APPLET_AID);
      byte[] instParams = Hex.decode("0F53746174757357616C6C657441707001000C313233343536373839303132");
      simulator.installApplet(appletAID, WalletApplet.class, instParams, (short) 0, (byte) instParams.length);
      cardTerminal = CardTerminalSimulator.terminal(simulator);
    } else {
      TerminalFactory tf = TerminalFactory.getDefault();

      for (CardTerminal t : tf.terminals().list()) {
        if (t.isCardPresent()) {
          cardTerminal = t;
          break;
        }
      }
    }
    Card apduCard = cardTerminal.connect("*");
    apduChannel = apduCard.getBasicChannel();
  }

  @BeforeEach
  void init() throws CardException {
    reset();
    cmdSet = new WalletAppletCommandSet(apduChannel);
  }

  @AfterEach
  void tearDown() throws CardException {
  }

  @AfterAll
  static void tearDownAll() {
  }

  private KeyPairGenerator keypairGenerator() throws Exception {
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
    g.initialize(ecSpec);

    return g;
  }


  @Test
  @DisplayName("SELECT command")
  void selectTest() throws CardException
  {
    ResponseAPDU response = cmdSet.select();
    assertEquals(0x9000, response.getSW());
  }

//  @Test
  @DisplayName("LOAD KEY and EXPORT KEY command")
  void loadKeyAndExportKeyTest() throws IOException, CipherException, CardException
  {
    Credentials wallet = Credentials.create(TEST_PRIVATE_KEY);

    ResponseAPDU response;
    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());
    response = cmdSet.loadKey(wallet.getEcKeyPair());
    assertEquals(0x9000, response.getSW());
    response = cmdSet.exportKey();
    assertEquals(0x9000, response.getSW());
    byte[] data = response.getData();


    // Assert that the exported public address is the right one
    assertEquals(wallet.getAddress(), convertECPublicKeyToAddress(data));
  }

  @Test
  @DisplayName("SIGN command")
  void signIntegrationTest() throws Exception
  {
    Credentials wallet = Credentials.create(TEST_PRIVATE_KEY);
    String toAddress = "0x64ef12BC968Fd3F5F8B63646Db27be92FF0fEC55";

    // Load Key on the card
    ResponseAPDU response;
    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());
    response = cmdSet.loadKey(wallet.getEcKeyPair());
    assertEquals(0x9000, response.getSW());

    // Create transaction
//    BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
    BigInteger gasPrice = new BigInteger("21000");
    BigInteger weiValue = Convert.toWei(BigDecimal.valueOf(1.0), Convert.Unit.FINNEY).toBigIntegerExact();
//    BigInteger nonce = web3j.ethGetTransactionCount(wallet.getAddress(), DefaultBlockParameterName.LATEST).send().getTransactionCount();
    BigInteger nonce = new BigInteger("35");
    System.out.println("To Address " + toAddress);
    RawTransaction rawTransaction = RawTransaction.createEtherTransaction(nonce, gasPrice, Transfer.GAS_LIMIT, toAddress, weiValue);
    byte[] txBytes = TransactionEncoder.encode(rawTransaction);

    // Sign the transaction on the card
    Sign.SignatureData signature = signMessage(txBytes);

    Web3j web3j = Web3j.build(new HttpService("https://ropsten.infura.io/uB6E6lwaacbBdi7rVDy7"));

    // Send the actual call to the blockchain
    Method encode = TransactionEncoder.class.getDeclaredMethod("encode", RawTransaction.class, Sign.SignatureData.class);
    encode.setAccessible(true);
    byte[] signedMessage = (byte[]) encode.invoke(null, rawTransaction, signature);
    String hexValue = "0x" + Hex.toHexString(signedMessage);
//    EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

//    if (ethSendTransaction.hasError()) {
//      System.out.println("Transaction Error: " + ethSendTransaction.getError().getMessage());
//    } else {
//      System.out.println(String.format("Sent Ether to %s from %s", toAddress, wallet.getAddress()));
//    }

  }


  @Data
  @NoArgsConstructor
  private static class TransactionDetails {
    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gasLimit;
    private String toAddress;
    private BigInteger value;
  }

  @Produces("application/json")
  @XmlRootElement
  @Data
  @NoArgsConstructor
  private static class ReceiveTransactionResponse
  {

    private String message;
    private TransactionDetails transactionDetails;
  }

  @Produces("application/json")
  @XmlRootElement
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  private static class CompleteTransactionRequest
  {

      private String respData;
      private String message;
      private TransactionDetails transactionDetails;
  }

//  @Test
  @DisplayName("Test backend + card")
  void signAndBackendTest() throws Exception
  {
    Credentials wallet = Credentials.create(TEST_PRIVATE_KEY);

    // Load Key on the card
    ResponseAPDU response;
    response = cmdSet.select();
    assertEquals(0x9000, response.getSW());
    response = cmdSet.loadKey(wallet.getEcKeyPair());
    assertEquals(0x9000, response.getSW());


    // get messageHash from API
    Client client = Client.create();
    WebResource webResource = client
            .resource("http://localhost:8080/transactions/receive");

    String input = "{\"fromAddress\": \"0x041fFAaB716DF567A31fb9673D0645D08Eb7E6c1\",  \"amount\": \"0.001\"}";

    ClientResponse clientResponse = webResource.type("application/json")
            .post(ClientResponse.class, input);

    ReceiveTransactionResponse output = clientResponse.getEntity(ReceiveTransactionResponse.class);


    System.out.println("message hash " + output.getMessage());

    byte[] messageHash = Base64.getDecoder().decode(output.getMessage());

    response = cmdSet.sign(messageHash);
    byte[] respData = response.getData();

    String respDataEncoded = new String(Base64.getEncoder().encode(respData));

    System.out.println(respDataEncoded);

    webResource = client
            .resource("http://localhost:8080/transactions/receive/complete");


    CompleteTransactionRequest requestData = new CompleteTransactionRequest(respDataEncoded, output.getMessage(),
            output.getTransactionDetails());

    clientResponse = webResource.type("application/json")
          .post(ClientResponse.class, requestData);

    String outputString = clientResponse.getEntity(String.class);

    System.out.println(outputString);
  }

  private Sign.SignatureData signMessage(byte[] message) throws Exception {
    byte[] messageHash = Hash.sha3(message);

    ResponseAPDU response = cmdSet.sign(messageHash);
    byte[] respData = response.getData();
    System.out.println(cmdSet.ByteArrayToHexString(respData));

    assertEquals(0x9000, response.getSW());
    byte[] rawSig = extractSignature(respData);

    int rLen = rawSig[3];
    int sOff = 6 + rLen;
    int sLen = rawSig.length - rLen - 6;

    System.out.println("rlen " + rLen);
    System.out.println("slen " + sLen);
    System.out.println("sOff " + sOff);

    BigInteger r = new BigInteger(Arrays.copyOfRange(rawSig, 4, 4 + rLen));
    BigInteger s = new BigInteger(Arrays.copyOfRange(rawSig, sOff, sOff + sLen));
    System.out.println(String.format("r: %s", r));
    System.out.println(String.format("s: %s", s));

    Class<?> ecdsaSignature = Class.forName("org.web3j.crypto.Sign$ECDSASignature");
    Constructor ecdsaSignatureConstructor = ecdsaSignature.getDeclaredConstructor(BigInteger.class, BigInteger.class);
    ecdsaSignatureConstructor.setAccessible(true);
    Object sig = ecdsaSignatureConstructor.newInstance(r, s);
    Method m = ecdsaSignature.getMethod("toCanonicalised");
    m.setAccessible(true);
    sig = m.invoke(sig);

    Method recoverFromSignature = Sign.class.getDeclaredMethod("recoverFromSignature", int.class, ecdsaSignature, byte[].class);
    recoverFromSignature.setAccessible(true);

    byte[] pubData = extractPublicKeyFromSignature(respData);

    BigInteger publicKey = convertECPublicKeyToBigInteger(pubData);

    System.out.println("publicKey: " + publicKey);

    int recId = -1;
    for (int i = 0; i < 4; i++) {
      BigInteger k = (BigInteger) recoverFromSignature.invoke(null, i, sig, messageHash);
      if (k != null && k.equals(publicKey)) {
        recId = i;
        break;
      }
    }
    if (recId == -1) {
      throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
    }

    int headerByte = recId + 27;

    Field rF = ecdsaSignature.getDeclaredField("r");
    rF.setAccessible(true);
    Field sF = ecdsaSignature.getDeclaredField("s");
    sF.setAccessible(true);
    r = (BigInteger) rF.get(sig);
    s = (BigInteger) sF.get(sig);

    // 1 header + 32 bytes for R + 32 bytes for S
    byte v = (byte) headerByte;
    byte[] rB = Numeric.toBytesPadded(r, 32);
    byte[] sB = Numeric.toBytesPadded(s, 32);

    return new Sign.SignatureData(v, rB, sB);
  }

  private byte[] extractPublicKeyFromSignature(byte[] sig) {
    assertEquals(WalletApplet.TLV_SIGNATURE_TEMPLATE, sig[0]);
    assertEquals((byte) 0x81, sig[1]);
    assertEquals(WalletApplet.TLV_PUB_KEY, sig[3]);

    return Arrays.copyOfRange(sig, 5, 5 + sig[4]);
  }

  private byte[] extractSignature(byte[] sig)
  {
    int off = sig[4] + 5;
    return Arrays.copyOfRange(sig, off, off + sig[off + 1] + 2);
  }

  public static String convertECPublicKeyToAddress(byte[] data) {

    return Numeric.prependHexPrefix(Keys.getAddress(convertECPublicKeyToBigInteger(data)));
  }

  public static BigInteger convertECPublicKeyToBigInteger(byte[] data) {
      byte[] newArray = Arrays.copyOfRange(data, 0, data.length);
      newArray[0] = 0x00;
      return new BigInteger(newArray);
  }


  private void reset() {
    if (USE_SIMULATOR) {
      simulator.reset();
    } else {
      apduChannel.getCard().getATR();
    }
  }
}
