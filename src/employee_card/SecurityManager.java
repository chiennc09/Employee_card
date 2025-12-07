package employee_card;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SecurityManager {

    // Config PIN & AES
    private static final byte[] DEFAULT_PIN = { '1', '2', '3', '4' };
    private static final byte MAX_RETRY = 3;
    private static final byte PIN_LEN = 8;
    
    private static final byte[] DEFAULT_AES_KEY = { 
        (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43, (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
        (byte)0x48, (byte)0x49, (byte)0x4A, (byte)0x4B, (byte)0x4C, (byte)0x4D, (byte)0x4E, (byte)0x4F 
    };

    private OwnerPIN pin;
    private AESKey aesKey;
    private Cipher aesCipher;
    
    // RSA Objects
    private KeyPair rsaKeyPair;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private Signature rsaSignature;

    private byte[] tempBuffer;

    public SecurityManager() {
        // 1. PIN
        pin = new OwnerPIN(MAX_RETRY, PIN_LEN);
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);

        try {
            // 2. AES (128 bit)
            aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            aesKey.setKey(DEFAULT_AES_KEY, (short) 0);
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            
            // 3. RSA (1024 bit)
			rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            rsaKeyPair.genKeyPair();
            privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
            publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
            
            rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            
            tempBuffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    // --- PIN ---
    public boolean verify(byte[] buf, short off, byte len) { return pin.check(buf, off, len); }
    public void changePin(byte[] buf, short off, byte len) { pin.update(buf, off, len); pin.check(buf, off, len); }
    public byte getTriesRemaining() { return pin.getTriesRemaining(); }
    public boolean isValidated() { return pin.isValidated(); }
    public void reset() { pin.reset(); }

    public boolean verifyEncryptedPin(byte[] buf, short off, short len) {
        if (len != 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(buf, off, len, tempBuffer, (short) 0);
        
        byte pinLen = 0;
        for (short i = 0; i < 16; i++) { if (tempBuffer[i] == (byte) 0xFF) break; pinLen++; }
        return pin.check(tempBuffer, (short) 0, pinLen);
    }

    // --- DATA ENCRYPTION (AES) ---
    
    public void decryptData(byte[] src, short srcOff, short len, byte[] dest, short destOff) {
        if (len % 16 != 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        short i = 0;
        while (i < len) {
            aesCipher.doFinal(src, (short)(srcOff + i), (short)16, dest, (short)(destOff + i));
            i += 16;
        }
    }

    public void encryptData(byte[] src, short srcOff, short len, byte[] dest, short destOff) {
        if (len % 16 != 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        short i = 0;
        while (i < len) {
            aesCipher.doFinal(src, (short)(srcOff + i), (short)16, dest, (short)(destOff + i));
            i += 16;
        }
    }

    // --- RSA AUTHENTICATION ---

    public short getPublicKey(byte[] dest, short off) {
        short modLen = publicKey.getModulus(dest, off);
        short expLen = publicKey.getExponent(dest, (short)(off + modLen));
        return (short)(modLen + expLen);
    }

    public short signData(byte[] input, short inputOff, short inputLen, byte[] sigBuff, short sigOff) {
        rsaSignature.init(privateKey, Signature.MODE_SIGN);
        return rsaSignature.sign(input, inputOff, inputLen, sigBuff, sigOff);
    }
}