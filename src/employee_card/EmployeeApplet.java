package employee_card;

import javacard.framework.*;

public class EmployeeApplet extends Applet {
    
    // INS Codes
    private static final byte INS_CHANGE_PIN     = (byte) 0x21;
    private static final byte INS_GET_RETRY      = (byte) 0x22;
    private static final byte INS_VERIFY_PIN     = (byte) 0x25;
    private static final byte INS_AUTHENTICATE   = (byte) 0x26; 
    private static final byte INS_GET_PUB_KEY    = (byte) 0x27;
    private static final byte INS_GET_SALT       = (byte) 0x28;
    private static final byte INS_GET_CHALLENGE  = (byte) 0x2F;

    private static final byte INS_SETUP_PIN      = (byte) 0x29;
    private static final byte INS_CHECK_SETUP    = (byte) 0x2A;

    // Admin
    private static final byte INS_LOCK_CARD      = (byte) 0x2B;
    private static final byte INS_UNLOCK_CARD    = (byte) 0x2C;
    private static final byte INS_RESET_PIN      = (byte) 0x2D;
    private static final byte INS_CHECK_LOCKED   = (byte) 0x2E;
    private static final byte INS_INJECT_ADMIN_KEY = (byte) 0x20;

    private static final byte INS_READ_INFO      = (byte) 0x30;
    private static final byte INS_UPDATE_INFO    = (byte) 0x31;
    // private static final byte INS_ADD_ACCESS_LOG = (byte) 0x40;
    // private static final byte INS_READ_LOGS      = (byte) 0x41;
    
    private static final byte INS_WALLET_TOPUP   = (byte) 0x50;
    private static final byte INS_WALLET_PAY     = (byte) 0x51;
    private static final byte INS_GET_BALANCE    = (byte) 0x52;
    // private static final byte INS_ADD_POINT      = (byte) 0x53;
    // private static final byte INS_GET_POINT      = (byte) 0x54;
    
    private static final byte INS_UPDATE_AVATAR   = (byte) 0x10;
    private static final byte INS_DOWNLOAD_AVATAR = (byte) 0x11;

    private static final short AVATAR_MAX_SIZE = (short) 8192;
    private static final short SW_EMP_ID_LOCKED  = (short) 0x6985;
    private static final short SW_AUTH_FAILED = (short) 0x6300;
    private static final short SW_CARD_LOCKED = (short) 0x6283; // M li th b kha

    private CardRepository repository;
    private SecurityManager security;
    private Avatar avatarObj;
    
    private byte[] tempCompBuffer;
    private byte[] tempBalance;

    protected EmployeeApplet() {
        repository = new CardRepository();
        security = new SecurityManager();
        
        try {
            avatarObj = new Avatar(AVATAR_MAX_SIZE);
        } catch (SystemException e) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        
        tempCompBuffer = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        tempBalance    = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EmployeeApplet();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            security.reset();
            return;
        }

        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];

        // --- BC 1: LC CC LNH QUN TR (LUN CHO PHP CHY) ---
        // Admin cn cc lnh ny  cu th hoc kim tra trng thi
        if (ins == INS_UNLOCK_CARD || ins == INS_CHECK_LOCKED || ins == INS_RESET_PIN || ins == INS_LOCK_CARD) {
            switch (ins) {
                case INS_CHECK_LOCKED:
                    buf[0] = security.isCardLocked() ? (byte) 1 : (byte) 0;
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                case INS_LOCK_CARD:
                    security.lockCard();
                    return;
                case INS_UNLOCK_CARD:
                    security.unlockCard();
                    return;
                case INS_RESET_PIN:
                    handleResetPin(apdu);
                    return;
            }
        }

        // --- BC 2: CHT CHN BO MT (QUAN TRNG NHT) ---
        // Nu th ang b kha, chn TT C cc lnh cn li ca User
        if (security.isCardLocked()) {
            ISOException.throwIt(SW_CARD_LOCKED); // Phn hi li 62 83
        }

        // --- BC 3: CC LNH BNH THNG CA USER ---
        switch (ins) {
            case INS_CHECK_SETUP:
                buf[0] = security.isPinSet() ? (byte) 1 : (byte) 0;
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                return;
                
            case INS_SETUP_PIN:
                handleSetupPin(apdu);
                return;
                
            case INS_GET_SALT:
                security.getSalt(buf, (short) 0);
                apdu.setOutgoingAndSend((short) 0, (short) 16);
                return;
                
            case INS_GET_CHALLENGE:
				security.generateChallenge(buf, (short) 0);
				apdu.setOutgoingAndSend((short) 0, (short) 16);
				return;
                
            case INS_VERIFY_PIN: 
                handleVerifyPin(apdu); 
                return;
                
            case INS_CHANGE_PIN:     
                handleChangePin(apdu); 
                return;
                
            case INS_GET_RETRY:
                buf[0] = security.getTriesRemaining();
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                return;
                
            case INS_UPDATE_AVATAR:
                handleUpdateAvatarEncrypted(apdu);
                return;
                
            case INS_DOWNLOAD_AVATAR:
                handleGetAvatarEncrypted(apdu);
                return;
                
            case INS_GET_PUB_KEY:  
                handleGetPublicKey(apdu); 
                return;
                
            case INS_AUTHENTICATE: 
                handleAuthenticateRSA(apdu); 
                return;
                
            case INS_READ_INFO:
                handleReadInfo(apdu);
                return;

            case INS_UPDATE_INFO:
                if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                handleUpdateInfo(apdu);
                return;

            // case INS_ADD_ACCESS_LOG: 
                // handleAddLog(apdu); 
                // return;
                
            // case INS_READ_LOGS:
                // if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                // handleReadLogs(apdu);
                // return;

            case INS_WALLET_TOPUP: 
                handleTopUp(apdu); 
                return;
                
            case INS_WALLET_PAY: 
                if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                handlePay(apdu); 
                return;
                
            case INS_GET_BALANCE: 
                if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                handleGetBalance(apdu); 
                return;
                
            // case INS_ADD_POINT: 
                // repository.addPoint(buf[ISO7816.OFFSET_P1]); 
                // return;
                
            // case INS_GET_POINT: 
                // short p = repository.getPoints(); 
                // buf[0] = (byte) p; 
                // apdu.setOutgoingAndSend((short)0, (short)1); 
                // return;
            case INS_INJECT_ADMIN_KEY:
				handleInjectAdminKey(apdu);
				break;

            default: 
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
	// Cập nhật hàm handle
	private void handleInjectAdminKey(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();
		
		// Gọi hàm giải mã RSA từ SecurityManager
		security.injectAdminKeyWithRSA(buf, ISO7816.OFFSET_CDATA, len);
	}
    // -------------------------------------------------------------
    
    private void handleSetupPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // Host gui 16 bytes Argon2 Hash xuong
        if (len != 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        security.setupFirstPin(buf, ISO7816.OFFSET_CDATA);
    }
    
    private void handleVerifyPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // Host gui Argon2 (16 bytes)

        if (len != 128) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        if (!security.verifyPin(buf, ISO7816.OFFSET_CDATA, len)) {
            // pinTries == 0 => 62 83
            if (security.isCardLocked()) {
                ISOException.throwIt(SW_CARD_LOCKED);
            }
            ISOException.throwIt(SW_AUTH_FAILED);// 0x6300
        }
    }

    private void handleChangePin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // Host gui Argon2 (16 bytes)
        if (len != 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        security.changePin(buf, ISO7816.OFFSET_CDATA);
    }

    private void handleResetPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len != 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        security.resetPin(buf, ISO7816.OFFSET_CDATA);
    }

    private void handleUpdateAvatarEncrypted(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short length = apdu.setIncomingAndReceive();
        if (length % 16 != 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        
        short chunkOffset = Util.makeShort(
			(byte) (buf[ISO7816.OFFSET_P1] & 0xFF), 
			(byte) (buf[ISO7816.OFFSET_P2] & 0xFF)
		);
		
        security.encryptData(buf, ISO7816.OFFSET_CDATA, length, buf, ISO7816.OFFSET_CDATA);
        
        avatarObj.setData(buf, ISO7816.OFFSET_CDATA, chunkOffset, length);
    }

    private void handleGetAvatarEncrypted(APDU apdu) {
        byte[] data = avatarObj.getData();
        short totalSize = avatarObj.getSize();
        
        short offset = Util.makeShort(
			(byte) (apdu.getBuffer()[ISO7816.OFFSET_P1] & 0xFF), 
			(byte) (apdu.getBuffer()[ISO7816.OFFSET_P2] & 0xFF)
		);
		
        short lenToRead = apdu.setOutgoing(); 
        
        if (totalSize == 0 || offset >= totalSize) 
        	ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        	
        if ((short)(offset + lenToRead) > totalSize) 
        	lenToRead = (short)(totalSize - offset);
        	
        apdu.setOutgoingLength(lenToRead);
        
        Util.arrayCopyNonAtomic(data, offset, apdu.getBuffer(), (short) 0, lenToRead);
        
        security.decryptData(apdu.getBuffer(), (short) 0, lenToRead, apdu.getBuffer(), (short) 0);
        
        apdu.sendBytes((short) 0, lenToRead);
    }

    private void handleGetPublicKey(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 
        short len = security.getPublicKey(buf, (short) 0); 
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    private void handleAuthenticateRSA(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 
        short len = apdu.setIncomingAndReceive();
        short sigLen = security.signData(buf, ISO7816.OFFSET_CDATA, len, buf, ISO7816.OFFSET_CDATA);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, sigLen);
    }
    
    private void handleReadInfo(APDU apdu) {
        if (!repository.isIdSet()) {
            Util.arrayFillNonAtomic(apdu.getBuffer(), (short)0, CardRepository.TOTAL_INFO_SIZE, (byte)0);
            apdu.setOutgoingAndSend((short) 0, CardRepository.TOTAL_INFO_SIZE);
            return;
        }

        byte[] buf = apdu.getBuffer();
        short off = 0;

        // 1. Decrypt ID -> buf
        security.decryptData(repository.getEncryptedId(), (short)0, CardRepository.LEN_ID, buf, off);
        off += CardRepository.LEN_ID;

        // 2. Decrypt Name -> buf
        security.decryptData(repository.getEncryptedName(), (short)0, CardRepository.LEN_NAME, buf, off);
        off += CardRepository.LEN_NAME;

        // 3. Decrypt DOB -> buf
        security.decryptData(repository.getEncryptedDob(), (short)0, CardRepository.LEN_DOB, buf, off);
        off += CardRepository.LEN_DOB;

        // 4. Decrypt Dept -> buf
        security.decryptData(repository.getEncryptedDept(), (short)0, CardRepository.LEN_DEPT, buf, off);
        off += CardRepository.LEN_DEPT;

        // 5. Decrypt Pos -> buf
        security.decryptData(repository.getEncryptedPos(), (short)0, CardRepository.LEN_POS, buf, off);
        off += CardRepository.LEN_POS;

        // => Host
        apdu.setOutgoingAndSend((short) 0, CardRepository.TOTAL_INFO_SIZE);
    }
    
    private void handleUpdateInfo(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // Check len
        if (len != CardRepository.TOTAL_INFO_SIZE) 
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // Check ID
        if (repository.isIdSet()) {
            // enc ID tu host
            security.encryptData(buf, ISO7816.OFFSET_CDATA, CardRepository.LEN_ID, tempCompBuffer, (short)0);
            
            // Compare vs encID
            if (Util.arrayCompare(tempCompBuffer, (short)0, repository.getEncryptedId(), (short)0, CardRepository.LEN_ID) != 0) {
                ISOException.throwIt(SW_EMP_ID_LOCKED);
            }
        }

        short currentOff = ISO7816.OFFSET_CDATA;

        // 1. Process ID
        security.encryptData(buf, currentOff, CardRepository.LEN_ID, tempCompBuffer, (short)0);
        repository.setEncryptedId(tempCompBuffer, (short)0);
        currentOff += CardRepository.LEN_ID;

        // 2. Process Name
        security.encryptData(buf, currentOff, CardRepository.LEN_NAME, tempCompBuffer, (short)0);
        repository.setEncryptedName(tempCompBuffer, (short)0);
        currentOff += CardRepository.LEN_NAME;

        // 3. Process DOB
        security.encryptData(buf, currentOff, CardRepository.LEN_DOB, tempCompBuffer, (short)0);
        repository.setEncryptedDob(tempCompBuffer, (short)0);
        currentOff += CardRepository.LEN_DOB;

        // 4. Process Dept
        security.encryptData(buf, currentOff, CardRepository.LEN_DEPT, tempCompBuffer, (short)0);
        repository.setEncryptedDept(tempCompBuffer, (short)0);
        currentOff += CardRepository.LEN_DEPT;

        // 5. Process Pos
        security.encryptData(buf, currentOff, CardRepository.LEN_POS, tempCompBuffer, (short)0);
        repository.setEncryptedPos(tempCompBuffer, (short)0);
    }

    private void handleGetBalance(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 
        byte[] encryptedBal = repository.getBalanceBuffer();
        Util.arrayFillNonAtomic(tempCompBuffer, (short)0, (short)16, (byte)0);
        if (Util.arrayCompare(encryptedBal, (short)0, tempCompBuffer, (short)0, (short)16) == 0) { 
            Util.arrayFillNonAtomic(buf, (short)0, (short)4, (byte)0); 
            apdu.setOutgoingAndSend((short) 0, (short) 4); 
            return; 
        }
        security.decryptData(encryptedBal, (short)0, (short)16, tempBalance, (short)0);
        Util.arrayCopyNonAtomic(tempBalance, (short) 12, buf, (short) 0, (short) 4); 
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }
    
    private void handleTopUp(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 
        short len = apdu.setIncomingAndReceive(); 
        if (len != 4) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte[] encryptedBal = repository.getBalanceBuffer();
        Util.arrayFillNonAtomic(tempCompBuffer, (short)0, (short)16, (byte)0);
        if (Util.arrayCompare(encryptedBal, (short)0, tempCompBuffer, (short)0, (short)16) == 0) 
            Util.arrayFillNonAtomic(tempBalance, (short)0, (short)16, (byte)0);
        else 
            security.decryptData(encryptedBal, (short)0, (short)16, tempBalance, (short)0);
        repository.addUnsigned32(tempBalance, (short) 12, buf, ISO7816.OFFSET_CDATA);
        security.encryptData(tempBalance, (short)0, (short)16, tempBalance, (short)0); 
        repository.setBalance(tempBalance, (short)0);
    }
    
    private void handlePay(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // Amount(4) + Time(4) + UN(4) = 12 bytes
        if (len != 12) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // Decrypt -> Check -> Tra tien)
        byte[] encryptedBal = repository.getBalanceBuffer();
        
        // Clear trc
        Util.arrayFillNonAtomic(tempCompBuffer, (short)0, (short)64, (byte)0);
        if (Util.arrayCompare(encryptedBal, (short)0, tempCompBuffer, (short)0, (short)16) == 0) 
            ISOException.throwIt((short) 0x6A84);
            
        security.decryptData(encryptedBal, (short)0, (short)16, tempBalance, (short)0);
        
        // tempBalance (offset 12) < Amount (Input offset CDATA)
        if (repository.compareUnsigned32(tempBalance, (short)12, buf, ISO7816.OFFSET_CDATA) < 0) 
            ISOException.throwIt((short) 0x6A84);
        
        // Tru tien
        repository.subUnsigned32(tempBalance, (short) 12, buf, ISO7816.OFFSET_CDATA);
        
        short lowAmount = Util.getShort(buf, (short) (ISO7816.OFFSET_CDATA + 2)); 
        if (lowAmount > 0) repository.addPoint((byte)(lowAmount / 10000));
        
        // save new bal (Encrypt -> Save)
        security.encryptData(tempBalance, (short)0, (short)16, tempBalance, (short)0); 
        repository.setBalance(tempBalance, (short)0);
        
        // [ID (16)] [Amount (4)] [Time (4)] [UN (4)]
        short off = 0;
        
        // Decrypt ID -> tempCompBuffer
        security.decryptData(repository.getEncryptedId(), (short)0, CardRepository.LEN_ID, tempCompBuffer, (short)0);
        off += 16;
        
        // Copy Amount (4 bytes)
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, tempCompBuffer, off, (short) 4);
        off += 4;
        
        // Copy Time (4 bytes)
        Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + 4), tempCompBuffer, off, (short) 4);
        off += 4;
        
        // Copy UN (4 bytes)
        Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + 8), tempCompBuffer, off, (short) 4);
        off += 4; 
        
        short sigLen = security.signData(tempCompBuffer, (short)0, off, buf, (short)0);
        
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }
    
    private void handleAddLog(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 
        short len = apdu.setIncomingAndReceive(); 
        if (len != 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        security.encryptData(buf, ISO7816.OFFSET_CDATA, (short) 32, buf, ISO7816.OFFSET_CDATA); 
        repository.addLog(buf, ISO7816.OFFSET_CDATA);
    }
    
    private void handleReadLogs(APDU apdu) {
        byte[] logs = repository.getLogBuffer(); 
        short total = repository.getTotalLogLen(); 
        if (logs[0] == 0) { 
            Util.arrayFillNonAtomic(apdu.getBuffer(), (short)0, total, (byte)0); 
            apdu.setOutgoingAndSend((short)0, total); 
            return; 
        }
        Util.arrayCopyNonAtomic(logs, (short)0, apdu.getBuffer(), (short)0, total);
        security.decryptData(apdu.getBuffer(), (short)0, total, apdu.getBuffer(), (short)0); 
        apdu.setOutgoingAndSend((short)0, total);
    }
}
