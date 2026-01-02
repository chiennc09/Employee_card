package employee_card;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SecurityManager {

    // Config
    private static final byte MAX_RETRY = 3;
    private static final byte AES_BLOCK_LEN = 16;
    private static final byte HASH_LEN = 20;

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
    private AESKey transientMasterKey; // Key nam tren RAM
    private AESKey wrapKey;            // Key dan xuat
    private Cipher aesCipher;          // Dung cho data encryption
    private Cipher keyWrapper;         // Dung cho key wrapping
    private MessageDigest sha1;

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
        isCardLocked = false;
        
        salt = new byte[16];
        encryptedMasterKey = new byte[AES_BLOCK_LEN];
        masterKeyHash = new byte[HASH_LEN];
        adminWrappedMasterKey = new byte[AES_BLOCK_LEN];
		// Khoi tao
        try {
        	// AES Key object
            transientMasterKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            wrapKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            
            // Ciphers
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            keyWrapper = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            
            // Hash
            sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            
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

    private void initSecureData() {
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        // Sinh salt
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
        
        // Sinh  Master Key 16 bytes
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rng.generateData(tempBuffer, (short) 0, (short) 16); 
        
        // Tinh Hash Master Key => EEPROM (verify pin)
        sha1.doFinal(tempBuffer, (short) 0, (short) 16, masterKeyHash, (short) 0);
        
        // Load Master Key vao RAM => sd ma hoa
        transientMasterKey.setKey(tempBuffer, (short) 0);
        
        // Set Key Argon2 
        wrapKey.setKey(keyBuffer, off);
        
        // Ma hoa Master Key (tempBuffer) -> Luu vao Blob EEPROM
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, encryptedMasterKey, (short) 0);
        
        // key admin
        wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, adminWrappedMasterKey, (short) 0);
        
        // Xoa temp
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)16, (byte)0);
        
        isPinSet = true;
        isValidated = true;
        isCardLocked = false;
        pinTries = MAX_RETRY;
    }

    // --- VERIFY PIN ---
    public boolean verifyPin(byte[] inputKey, short off) {
        if (!isPinSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        
<<<<<<< HEAD
        //  KIM TRA KHĂ“A ADMIN TRÆ¯C (Æ¯u tiĂªn cao nht)
        if (isCardLocked) ISOException.throwIt((short) 0x6283); 
        
        // Sau Ä‘Ă³ mi kim tra pinTries
=======
        // KIEM TRA KHÓA ADMIN TRƯC (Ưu tiên cao nht)
        if (isCardLocked) ISOException.throwIt((short) 0x6283); 
        
        // Sau đó kiem tra pinTries
>>>>>>> b579651219a4f3fcbd3dcf88223b7cd8e0124544
        if (pinTries == 0) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		// 1. Set Key dan xuat
        wrapKey.setKey(inputKey, off);
        
        // 2. Giai ma Encrypted Blob trong EEPROM -> Ra Key tam
        keyWrapper.init(wrapKey, Cipher.MODE_DECRYPT);
        
        // tempBuffer[0..15] chua ket qua giai ma (Candidate Master Key)
        keyWrapper.doFinal(encryptedMasterKey, (short) 0, (short) 16, tempBuffer, (short) 0);
        
        // 3. Hash Candidate Key
        // tempBuffer[16..47] chua Hash masterKey
        sha1.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16);

		// 4. So sanh voi Hash goc (masterKeyHash)
        boolean match = (Util.arrayCompare(tempBuffer, (short) 16, masterKeyHash, (short) 0, HASH_LEN) == 0);

        if (match) {
            pinTries = MAX_RETRY;// Reset retry
            isValidated = true;
            transientMasterKey.setKey(tempBuffer, (short)0);
            Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)64, (byte)0);
            return true;
        } else {
            pinTries--;
            isValidated = false;
            transientMasterKey.clearKey();
            
<<<<<<< HEAD
            //  T ÄNG KHĂ“A KHI NHP SAI 3 LN
=======
>>>>>>> b579651219a4f3fcbd3dcf88223b7cd8e0124544
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

		// 1. Lay Master Key tu RAM ra temp
        transientMasterKey.getKey(tempBuffer, (short) 0);
        
        // 2. Set new Key Argon2
        wrapKey.setKey(newKey, off);
        
        // 3. Ma hoa Master Key = new key -> Ghi de vao Blob
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, tempBuffer, (short) 16); 
        
        if (Util.arrayCompare(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16) == 0) {
            ISOException.throwIt(SW_PIN_IDENTICAL);
        }
        
        Util.arrayCopyNonAtomic(tempBuffer, (short) 16, encryptedMasterKey, (short) 0, (short) 16);
        
        //set key admin
        wrapKey.setKey(ADMIN_STATIC_KEY, (short) 0);
        keyWrapper.init(wrapKey, Cipher.MODE_ENCRYPT);
        keyWrapper.doFinal(tempBuffer, (short) 0, (short) 16, adminWrappedMasterKey, (short) 0);
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)32, (byte)0);
    }

<<<<<<< HEAD
    //  Admin khĂ³a th - HOT ÄNG TRC TIP
=======
>>>>>>> b579651219a4f3fcbd3dcf88223b7cd8e0124544
    public void lockCard() {
        isCardLocked = true;
        isValidated = false;
        transientMasterKey.clearKey();
        pinTries = 0; 
    }

<<<<<<< HEAD
    //  Admin m khĂ³a th - HOT ÄNG TRC TIP
=======
>>>>>>> b579651219a4f3fcbd3dcf88223b7cd8e0124544
    public void unlockCard() {
        isCardLocked = false;
        pinTries = MAX_RETRY;
        isValidated = false;
        transientMasterKey.clearKey();
    }

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
        // Reset xong khĂ´ng t Ä‘ng validate, User vn phi verifyPin bng m mi
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

	// [Len Modulus (2b)] [Modulus Data] [Len Exponent (2b)] [Exponent Data]
    public short getPublicKey(byte[] dest, short off) {
        // 2 byte dau ghi len Modulus
        short modLen = publicKey.getModulus(dest, (short)(off + 2));
        Util.setShort(dest, off, modLen);
        
        short expOff = (short)(off + 2 + modLen);
        // 2 byte tiep ghi len Exponent
        short expLen = publicKey.getExponent(dest, (short)(expOff + 2));
        Util.setShort(dest, expOff, expLen);
        
        return (short)(2 + modLen + 2 + expLen);
    }

    public short signData(byte[] input, short inputOff, short inputLen, byte[] sigBuff, short sigOff) {
        if (!isValidated) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        rsaSignature.init(privateKey, Signature.MODE_SIGN);
        return rsaSignature.sign(input, inputOff, inputLen, sigBuff, sigOff);
    }
    // ThĂªm hĂ m xĂ¡c thc Admin mi
	public void verifyAdmin(byte[] inputKey, short off) {
		// So sĂ¡nh key gi lĂªn vi ADMIN_STATIC_KEY (ADMIN_KEY_2025...)
		if (Util.arrayCompare(inputKey, off, ADMIN_STATIC_KEY, (short) 0, (short) 16) == 0) {
			isAdminValidated = true;
			
			// QUAN TRNG: Admin cng cn np MasterKey Ä‘ cĂ³ quyn Encrypt d liu khi Update Info
			// DĂ¹ng cÆ¡ ch Unwrapping ging nhÆ° lĂºc Reset PIN
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