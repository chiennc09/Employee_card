package employee_card;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SecurityManager {

    // Config
    private static final byte MAX_RETRY = 3;
    private static final byte AES_BLOCK_LEN = 16;
    private static final byte HASH_LEN = 20; // SHA-1 cho Java Card 2.2.1

    private static final short SW_PIN_IDENTICAL = (short) 0x6A89; 

    private boolean isValidated;
    private byte pinTries;
    private boolean isPinSet;
    private boolean isCardLocked;
    private byte[] adminWrappedMasterKey;
    private boolean isAdminValidated = false;
    
    private static final byte[] ADMIN_STATIC_KEY = {
        0x41, 0x44, 0x4D, 0x49, 0x4E, 0x5F, 0x4B, 0x45,
        0x59, 0x5F, 0x32, 0x30, 0x32, 0x35, 0x00, 0x00
    };

    // Crypto
    private AESKey transientMasterKey;
    private AESKey wrapKey;
    private Cipher aesCipher;
    private Cipher keyWrapper;
    private MessageDigest sha1;

    // D liu EEPROM
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
        adminWrappedMasterKey = new byte[AES_BLOCK_LEN];

        try {
            transientMasterKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            wrapKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            keyWrapper = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            
            rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            rsaKeyPair.genKeyPair();
            privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
            publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
            rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            
            tempBuffer = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
            initSecureData();
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    private void initSecureData() {
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rng.generateData(salt, (short) 0, (short) 16);
    }

    public void getSalt(byte[] dest, short off) {
        Util.arrayCopyNonAtomic(salt, (short) 0, dest, off, (short) 16);
    }
    
    public boolean isPinSet() { return isPinSet; }
    public byte getTriesRemaining() { return pinTries; }
    public boolean isValidated() { return isValidated; }
    public boolean isCardLocked() { return isCardLocked; }

    public void reset() {
        isValidated = false;
        isAdminValidated = false;
        transientMasterKey.clearKey();
    }
    
    public void setupFirstPin(byte[] keyBuffer, short off) {
        if (isPinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rng.generateData(tempBuffer, (short) 0, (short) 16); 
        sha1.doFinal(tempBuffer, (short) 0, (short) 16, masterKeyHash, (short) 0);
        transientMasterKey.setKey(tempBuffer, (short) 0);
        wrapKey.setKey(keyBuffer, off);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, encryptedMasterKey, (short) 0);
        wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, adminWrappedMasterKey, (short) 0);
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)16, (byte)0);
        isPinSet = true;
        isValidated = true;
        isCardLocked = false;
        pinTries = MAX_RETRY;
    }

    // --- VERIFY PIN ---
    public boolean verifyPin(byte[] inputKey, short off) {
        if (!isPinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        
        //  KIM TRA KHÓA ADMIN TRƯC (Ưu tiên cao nht)
        if (isCardLocked) ISOException.throwIt((short) 0x6283); 
        
        // Sau đó mi kim tra pinTries
        if (pinTries == 0) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        wrapKey.setKey(inputKey, off);
        keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
        keyWrapper.doFinal(encryptedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0);
        sha1.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16);

        boolean match = (Util.arrayCompare(tempBuffer, (short) 16, masterKeyHash, (short) 0, HASH_LEN) == 0);

        if (match) {
            pinTries = MAX_RETRY;
            isValidated = true;
            transientMasterKey.setKey(tempBuffer, (short)0);
            Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)64, (byte)0);
            return true;
        } else {
            pinTries--;
            isValidated = false;
            transientMasterKey.clearKey();
            
            //  T ĐNG KHÓA KHI NHP SAI 3 LN
            if (pinTries == 0) {
                isCardLocked = true; 
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)64, (byte)0);
            return false;
        }
    }

    public void changePin(byte[] newKey, short off) {
        if (!isValidated || !transientMasterKey.isInitialized()) 
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        transientMasterKey.getKey(tempBuffer, (short) 0);
        wrapKey.setKey(newKey, off);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16); 
        if (Util.arrayCompare(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16) == 0) {
            ISOException.throwIt(SW_PIN_IDENTICAL);
        }
        Util.arrayCopyNonAtomic(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16);
        wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, adminWrappedMasterKey, (short) 0);
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)32, (byte)0);
    }

    //  Admin khóa th - HOT ĐNG TRC TIP
    public void lockCard() {
        isCardLocked = true;
        isValidated = false;
        transientMasterKey.clearKey();
        pinTries = 0; 
    }

    //  Admin m khóa th - HOT ĐNG TRC TIP
    public void unlockCard() {
        isCardLocked = false;
        pinTries = MAX_RETRY;
        isValidated = false;
        transientMasterKey.clearKey();
    }

    //  Admin Reset PIN - S dng Admin Key tnh
    public void resetPin(byte[] newKeyBuffer, short off) {
        wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
        keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
        keyWrapper.doFinal(adminWrappedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0); 

        wrapKey.setKey(newKeyBuffer, off);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16); 

        if (Util.arrayCompare(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16) == 0) {
            Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)32, (byte)0);
            ISOException.throwIt(SW_PIN_IDENTICAL);
        }

        Util.arrayCopyNonAtomic(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16);
        wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, adminWrappedMasterKey, (short) 0);

        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)32, (byte)0);
        pinTries = MAX_RETRY;
        isCardLocked = false;
        // Reset xong không t đng validate, User vn phi verifyPin bng m mi
        isValidated = false; 
    }

    public void encryptData(byte[] src, short srcOff, short len, byte[] dest, short destOff) {
        if (!transientMasterKey.isInitialized()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        aesCipher.init(transientMasterKey, Cipher.MODE_ENCRYPT);
        aesCipher.doFinal(src, srcOff, len, dest, destOff);
    }

    public void decryptData(byte[] src, short srcOff, short len, byte[] dest, short destOff) {
        if (!transientMasterKey.isInitialized()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        aesCipher.init(transientMasterKey, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(src, srcOff, len, dest, destOff);
    }

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
    // Thêm hàm xác thc Admin mi
	public void verifyAdmin(byte[] inputKey, short off) {
		// So sánh key gi lên vi ADMIN_STATIC_KEY (ADMIN_KEY_2025...)
		if (Util.arrayCompare(inputKey, off, ADMIN_STATIC_KEY, (short) 0, (short) 16) == 0) {
			isAdminValidated = true;
			
			// QUAN TRNG: Admin cng cn np MasterKey đ có quyn Encrypt d liu khi Update Info
			// Dùng cơ ch Unwrapping ging như lúc Reset PIN
			wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
			keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
			keyWrapper.doFinal(adminWrappedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0);
			transientMasterKey.setKey(tempBuffer, (short) 0);
		} else {
			isAdminValidated = false;
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}

	public boolean isAdminValidated() {
		return isAdminValidated;
	}
}
