package employee_card;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SecurityManager {

    // Config
    private static final byte MAX_RETRY = 3;
    private static final byte AES_BLOCK_LEN = 16;
    private static final byte HASH_LEN = 32; // SHA-256

    private boolean isValidated;
    private byte pinTries;
    private boolean isPinSet;

    // Crypto
    private AESKey transientMasterKey; // Key nam tren RAM
    private AESKey wrapKey;            // Key dan xuat
    private Cipher aesCipher;          // Dung cho data encryption
    private Cipher keyWrapper;         // Dung cho key wrapping
    private MessageDigest sha256;      

    // Du lieu luu trong EEPROM
    private byte[] salt;               
    private byte[] encryptedMasterKey; // Khoa chu da ma hoa (Blob)
    private byte[] masterKeyHash;     
    
    private byte[] tempBuffer;
    
    // RSA Objects
    private KeyPair rsaKeyPair;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private Signature rsaSignature;

    public SecurityManager() {
    	isPinSet = false;
        isValidated = false;
        pinTries = MAX_RETRY;
        
        salt = new byte[16];
        encryptedMasterKey = new byte[AES_BLOCK_LEN];
        masterKeyHash = new byte[HASH_LEN];

        // Khoi tao
        try {
            // AES Key object
            transientMasterKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            wrapKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            
            // Ciphers
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            keyWrapper = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            
            // Hash
            sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            
            // RSA 
            rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            rsaKeyPair.genKeyPair();
            privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
            publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
            rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

            tempBuffer = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);

            // SETUP
            initSecureData();

        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    /// --- SETUP ---
    
    private void initSecureData() {
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        // Sinh salt
        rng.generateData(salt, (short) 0, (short) 16);
        
        isPinSet = false;
        isValidated = false;
    }

    public void getSalt(byte[] dest, short off) {
        Util.arrayCopyNonAtomic(salt, (short) 0, dest, off, (short) 16);
    }
    
    public boolean isPinSet() {
        return isPinSet;
    }
    public byte getTriesRemaining() { return pinTries; }
    public boolean isValidated() { return isValidated; }

    public void reset() {
        isValidated = false;
        transientMasterKey.clearKey();
    }
    
    public void setupFirstPin(byte[] keyBuffer, short off) {
        if (isPinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        // Sinh  Master Key 16 bytes
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rng.generateData(tempBuffer, (short) 0, (short) 16); 

        // Tinh Hash Master Key => EEPROM (verify pin)
        sha256.doFinal(tempBuffer, (short) 0, (short) 16, masterKeyHash, (short) 0);

        // Load Master Key vao RAM => sd ma hoa
        transientMasterKey.setKey(tempBuffer, (short) 0);
        
        // Set Key Argon2 
        wrapKey.setKey(keyBuffer, off);

        // Ma hoa Master Key (tempBuffer) -> Luu vo Blob EEPROM
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, encryptedMasterKey, (short) 0);

        // Xoa temp 
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)16, (byte)0);

        isPinSet = true;
        isValidated = true;
    }

    // --- (VERIFY) ---
    // inputKey: key tu PIN (16 bytes)
    public boolean verifyPin(byte[] inputKey, short off) {
    	if (!isPinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (pinTries == 0) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); // check

        // 1. Set Key dan xuat
        wrapKey.setKey(inputKey, off);

        // 2. Giai ma Encrypted Blob trong EEPROM -> Ra Key tam
        keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
        // tempBuffer[0..15] chua ket qua giai ma (Candidate Master Key)
        keyWrapper.doFinal(encryptedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0);

        // 3. Hash Candidate Key
        // tempBuffer[16..47] chua Hash masterKey
        sha256.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16);

        // 4. So sanh voi Hash goc (masterKeyHash)
        boolean match = (Util.arrayCompare(tempBuffer, (short) 16, masterKeyHash, (short) 0, HASH_LEN) == 0);

        // Clear tempBuffer
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)64, (byte)0);

        if (match) {
            pinTries = MAX_RETRY; // Reset retry
            isValidated = true;
            
            // Load lai Master Key vao RAM => ma hoa
            keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
            keyWrapper.doFinal(encryptedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0);
            transientMasterKey.setKey(tempBuffer, (short)0);
            Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)16, (byte)0);
            return true;
        } else {
            // SAI PIN
            pinTries--;
            isValidated = false;
            transientMasterKey.clearKey();
            if (pinTries == 0) {}
            return false;
        }
    }

    public void changePin(byte[] newKey, short off) {
        if (!isValidated || !transientMasterKey.isInitialized()) 
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        // 1. Lay Master Key tu RAM ra temp
        transientMasterKey.getKey(tempBuffer, (short) 0);

        // 2. Set new Key Argon2
        wrapKey.setKey(newKey, off);

        // 3. Ma hoa Master Key = new key -> Ghi e vao Blob
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, encryptedMasterKey, (short) 0);

        // Xoa temp
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)16, (byte)0);
    }

    // --- DATA ENCRYPTION / DECRYPTION  ---
    public void encryptData(byte[] src, short srcOff, short len, byte[] dest, short destOff) {
        if (!transientMasterKey.isInitialized()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (len % 16 != 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        
        aesCipher.init(transientMasterKey, Cipher.MODE_ENCRYPT);
        aesCipher.doFinal(src, srcOff, len, dest, destOff);
    }

    public void decryptData(byte[] src, short srcOff, short len, byte[] dest, short destOff) {
        if (!transientMasterKey.isInitialized()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if (len % 16 != 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        aesCipher.init(transientMasterKey, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(src, srcOff, len, dest, destOff);
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