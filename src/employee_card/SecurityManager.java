package employee_card;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SecurityManager {

    // Config
    private static final byte MAX_RETRY = 3;
    private static final byte AES_BLOCK_LEN = 16;
    private static final byte HASH_LEN = 32; // SHA-256

    //  THÊM: M li tùy chnh cho PIN trùng
    private static final short SW_PIN_IDENTICAL = (short) 0x6A89; // PIN mi trùng PIN c

    private boolean isValidated;
    private byte pinTries;
    private boolean isPinSet;
    private boolean isCardLocked;
    private byte[] adminWrappedMasterKey;
    private static final byte[] ADMIN_STATIC_KEY = {
        0x41, 0x44, 0x4D, 0x49, 0x4E, 0x5F, 0x4B, 0x45,
        0x59, 0x5F, 0x32, 0x30, 0x32, 0x35, 0x00, 0x00
    };

    // Crypto
    private AESKey transientMasterKey;
    private AESKey wrapKey;
    private Cipher aesCipher;
    private Cipher keyWrapper;
    private MessageDigest sha256;

    // D liu lýu trong EEPROM
    private byte[] salt;
    private byte[] encryptedMasterKey;
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
        isCardLocked = false;
        
        salt = new byte[16];
        encryptedMasterKey = new byte[AES_BLOCK_LEN];
        masterKeyHash = new byte[HASH_LEN];

        try {
            transientMasterKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            wrapKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            keyWrapper = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            
            sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            
            rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            rsaKeyPair.genKeyPair();
            privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
            publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
            rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            
            adminWrappedMasterKey = new byte[AES_BLOCK_LEN];

            tempBuffer = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);

            initSecureData();

        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    /// --- SETUP ---
    
    private void initSecureData() {
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
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
    
    public byte getTriesRemaining() { 
        return pinTries; 
    }
    
    public boolean isValidated() { 
        return isValidated; 
    }
    
    public boolean isCardLocked() {
        return isCardLocked;
    }

    public void reset() {
        isValidated = false;
        transientMasterKey.clearKey();
    }
    
    public void setupFirstPin(byte[] keyBuffer, short off) {
        if (isPinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rng.generateData(tempBuffer, (short) 0, (short) 16); 

        sha256.doFinal(tempBuffer, (short) 0, (short) 16, masterKeyHash, (short) 0);
        transientMasterKey.setKey(tempBuffer, (short) 0);
        
        // User's wrapped key
        wrapKey.setKey(keyBuffer, off);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, encryptedMasterKey, (short) 0);

        // Admin's wrapped key (backup)
        wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, adminWrappedMasterKey, (short) 0);

        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)16, (byte)0);

        isPinSet = true;
        isValidated = true;
        isCardLocked = false;
    }

    // --- VERIFY PIN ---
    public boolean verifyPin(byte[] inputKey, short off) {
        if (!isPinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        
        if (isCardLocked) ISOException.throwIt((short) 0x6283);
        
        if (pinTries == 0) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        wrapKey.setKey(inputKey, off);

        keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
        keyWrapper.doFinal(encryptedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0);

        sha256.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16);

        boolean match = (Util.arrayCompare(tempBuffer, (short) 16, masterKeyHash, (short) 0, HASH_LEN) == 0);

        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)64, (byte)0);

        if (match) {
            pinTries = MAX_RETRY;
            isValidated = true;
            
            keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
            keyWrapper.doFinal(encryptedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0);
            transientMasterKey.setKey(tempBuffer, (short)0);
            Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)16, (byte)0);
            return true;
        } else {
            pinTries--;
            isValidated = false;
            transientMasterKey.clearKey();
            
            if (pinTries == 0) {
                isCardLocked = true;
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return false;
        }
    }

    //  CP NHT: Ði PIN vi kim tra trùng
    public void changePin(byte[] newKey, short off) {
    if (!isValidated || !transientMasterKey.isInitialized()) 
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

    // BÝC 1: Kim tra trùng PIN bng cách so sánh Hash
    // unwrap PIN mi ð ly Master Key gi ðnh
    wrapKey.setKey(newKey, off);
    keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
    
    // To hash ca PIN mi (PIN mi ð là hash t client, ta ly hash thêm ln na ð so sánh)
    // Hoc cách chun nht: Dùng Master Key ðang có trong RAM (transientMasterKey) 
    // ð gi lp vic wrap PIN mi ri so sánh vi bn lýu EEPROM.
    
    // CÁCH ÐÕN GIN VÀ AN TOÀN NHT:
    // Th wrap Master Key hin ti bng PIN mi, nu kt qu ging ht encryptedMasterKey c -> PIN TRÙNG
    transientMasterKey.getKey(tempBuffer, (short) 0); // Ly Master Key tht ra
    wrapKey.setKey(newKey, off);
    keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
    keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16); // Kt qu wrap th
    
    if (Util.arrayCompare(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16) == 0) {
        ISOException.throwIt(SW_PIN_IDENTICAL); // 6A 89
    }

    // BÝC 2: Nu không trùng, thc hin ði PIN nhý c
    Util.arrayCopyNonAtomic(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16);
    
    // Cp nht luôn bn cho Admin
    wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
    keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
    keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, adminWrappedMasterKey, (short) 0);
    
    Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)32, (byte)0);
	}

    // Admin khóa th
    public void lockCard() {
        isCardLocked = true;
        isValidated = false;
        transientMasterKey.clearKey();
    }

    // Admin m khóa th
    public void unlockCard() {
        isCardLocked = false;
        pinTries = MAX_RETRY;
        isValidated = false;
        transientMasterKey.clearKey();
    }

    public void resetPin(byte[] newKeyBuffer, short off) {
    // Býc 1: Ly Master Key tht ra bng Admin Key (Luôn thành công v Admin Key là tnh)
    wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
    keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
    keyWrapper.doFinal(adminWrappedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0); 
    // Lúc này Master Key tht ðang nm  tempBuffer[0..15]

    // Býc 2: Kim tra xem PIN mi có trùng PIN c không (Không dùng try-catch crypto)
    // Ta ly Master Key tht va có, th Wrap nó bng PIN mi
    wrapKey.setKey(newKeyBuffer, off);
    keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
    keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16); 
    // Kt qu wrap th nm  tempBuffer[16..31]

    // So sánh bn wrap th vi bn encryptedMasterKey hin ti trong EEPROM
    if (Util.arrayCompare(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16) == 0) {
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)32, (byte)0);
        ISOException.throwIt((short) 0x6A89); // Li PIN trùng (SW_PIN_IDENTICAL)
    }

    // Býc 3: Nu không trùng, tin hành ghi ðè nhý bnh thýng
    transientMasterKey.setKey(tempBuffer, (short) 0); // Np vào RAM
    Util.arrayCopyNonAtomic(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16);
    
    // Cp nht li adminWrappedMasterKey (ð phng Master Key b thay ði)
    wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
    keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
    keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, adminWrappedMasterKey, (short) 0);

    Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)32, (byte)0);
    pinTries = MAX_RETRY;
    isCardLocked = false;
    isValidated = true;
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
        short modLen = publicKey.getModulus(dest, (short)(off + 2));
        Util.setShort(dest, off, modLen);
        
        short expOff = (short)(off + 2 + modLen);
        short expLen = publicKey.getExponent(dest, (short)(expOff + 2));
        Util.setShort(dest, expOff, expLen);
        
        return (short)(2 + modLen + 2 + expLen);
    }

    public short signData(byte[] input, short inputOff, short inputLen, byte[] sigBuff, short sigOff) {
        if (!isValidated) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        rsaSignature.init(privateKey, Signature.MODE_SIGN);
        return rsaSignature.sign(input, inputOff, inputLen, sigBuff, sigOff);
    }
}