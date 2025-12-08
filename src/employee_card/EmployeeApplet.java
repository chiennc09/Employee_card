package employee_card;

import javacard.framework.*;

public class EmployeeApplet extends Applet {
	
	// INS Codes
	private static final byte INS_CHANGE_PIN     = (byte) 0x21;
	private static final byte INS_GET_RETRY      = (byte) 0x22;
    private static final byte INS_VERIFY_PIN_ENC = (byte) 0x25; 
    private static final byte INS_AUTHENTICATE   = (byte) 0x26; 
    private static final byte INS_VERIFY_PIN     = (byte) 0x25;
    private static final byte INS_GET_PUB_KEY    = (byte) 0x27;
    private static final byte INS_GET_SALT       = (byte) 0x28;

    private static final byte INS_SETUP_PIN      = (byte) 0x29;
    private static final byte INS_CHECK_SETUP    = (byte) 0x2A;

    private static final byte INS_READ_INFO      = (byte) 0x30;
    private static final byte INS_UPDATE_INFO    = (byte) 0x31;
    private static final byte INS_ADD_ACCESS_LOG = (byte) 0x40;
    private static final byte INS_READ_LOGS      = (byte) 0x41;
    
    private static final byte INS_WALLET_TOPUP   = (byte) 0x50;
    private static final byte INS_WALLET_PAY     = (byte) 0x51;
    private static final byte INS_GET_BALANCE    = (byte) 0x52;
    private static final byte INS_ADD_POINT      = (byte) 0x53;
    private static final byte INS_GET_POINT      = (byte) 0x54;
    
    // INS Avatar (Ma hoa)
    private static final byte INS_UPDATE_AVATAR   = (byte) 0x10;
    private static final byte INS_DOWNLOAD_AVATAR = (byte) 0x11;

    // Size 8KB
    private static final short AVATAR_MAX_SIZE = (short) 8192;
    private static final short SW_EMP_ID_LOCKED  = (short) 0x6985;
    private static final short SW_AUTH_FAILED = (short) 0x6300;

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

        switch (ins) {
        	case INS_CHECK_SETUP:
                // Tr v 0x01 nu  set, 0x00 nu cha set
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
            case INS_GET_PUB_KEY:  handleGetPublicKey(apdu); return;
            case INS_AUTHENTICATE: handleAuthenticateRSA(apdu); return;
            case INS_READ_INFO:
                if (!repository.isIdSet()) {
                    Util.arrayFillNonAtomic(buf, (short)0, CardRepository.EMP_INFO_MAX, (byte)0);
                    apdu.setOutgoingAndSend((short) 0, CardRepository.EMP_INFO_MAX);
                    return;
                }
                byte[] encryptedInfo = repository.getEmpInfoBuffer();
                security.decryptData(encryptedInfo, (short)0, CardRepository.EMP_INFO_MAX, buf, (short)0);
                apdu.setOutgoingAndSend((short) 0, CardRepository.EMP_INFO_MAX);
                return;

            case INS_UPDATE_INFO:
                if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                handleUpdateInfo(apdu);
                return;

            case INS_ADD_ACCESS_LOG: handleAddLog(apdu); return;
            case INS_READ_LOGS:
                if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                handleReadLogs(apdu);
                return;

            case INS_WALLET_TOPUP: handleTopUp(apdu); return;
            case INS_WALLET_PAY: 
                if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                handlePay(apdu); return;
            case INS_GET_BALANCE: 
                if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                handleGetBalance(apdu); return;
            case INS_ADD_POINT: repository.addPoint(buf[ISO7816.OFFSET_P1]); return;
            case INS_GET_POINT: 
                short p = repository.getPoints(); buf[0] = (byte) p; 
                apdu.setOutgoingAndSend((short)0, (short)1); return;

            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
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
        if (len != 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        if (!security.verifyPin(buf, ISO7816.OFFSET_CDATA)) {
            ISOException.throwIt(SW_AUTH_FAILED); // 0x6300
        }
    }

    private void handleChangePin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // Host gui Argon2 (16 bytes)
        if (len != 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        security.changePin(buf, ISO7816.OFFSET_CDATA);
    }

    // ---UPLOAD (ENCRYPTED) ---
    private void handleUpdateAvatarEncrypted(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short length = apdu.setIncomingAndReceive();
        
        // Bt buc chia ht cho 16  m ha
        if (length % 16 != 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        short chunkOffset = Util.makeShort(
            (byte) (buf[ISO7816.OFFSET_P1] & 0xFF), 
            (byte) (buf[ISO7816.OFFSET_P2] & 0xFF)
        );
        
        // 1. M ha d liu ngay trong buffer (Plain -> Cipher)
        security.encryptData(buf, ISO7816.OFFSET_CDATA, length, buf, ISO7816.OFFSET_CDATA);
        
        // 2. Lu Ciphertext vo EEPROM
        avatarObj.setData(buf, ISO7816.OFFSET_CDATA, chunkOffset, length);
    }

    // --- DOWNLOAD (ENCRYPTED) ---
    private void handleGetAvatarEncrypted(APDU apdu) {
        byte[] data = avatarObj.getData(); // D liu ny ang b m ha
        short totalSize = avatarObj.getSize();
        
        short offset = Util.makeShort(
            (byte) (apdu.getBuffer()[ISO7816.OFFSET_P1] & 0xFF), 
            (byte) (apdu.getBuffer()[ISO7816.OFFSET_P2] & 0xFF)
        );
        
        short lenToRead = apdu.setOutgoing(); 
        
        if (totalSize == 0 || offset >= totalSize) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        if ((short)(offset + lenToRead) > totalSize) lenToRead = (short)(totalSize - offset);
        
        // m bo block 16 bytes khi gii m
        // (Client nn gi Le = 240, nhng nu l byte cui th phi x l cn thn hoc chp nhn li padding)
        //  y gi nh Client lun xin bi s ca 16
        
        apdu.setOutgoingLength(lenToRead);
        
        // 1. Copy Ciphertext ra Buffer gi
        Util.arrayCopyNonAtomic(data, offset, apdu.getBuffer(), (short) 0, lenToRead);
        
        // 2. Gii m ti ch (Cipher -> Plain)  gi v Client
        security.decryptData(apdu.getBuffer(), (short) 0, lenToRead, apdu.getBuffer(), (short) 0);
        
        // 3. Gi Plaintext
        apdu.sendBytes((short) 0, lenToRead);
    }

    private void handleGetPublicKey(APDU apdu) {
        byte[] buf = apdu.getBuffer(); short len = security.getPublicKey(buf, (short) 0); apdu.setOutgoingAndSend((short) 0, len);
    }
    private void handleAuthenticateRSA(APDU apdu) {
        byte[] buf = apdu.getBuffer(); short len = apdu.setIncomingAndReceive();
        short sigLen = security.signData(buf, ISO7816.OFFSET_CDATA, len, buf, ISO7816.OFFSET_CDATA);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, sigLen);
    }
    private void handleUpdateInfo(APDU apdu) {
        byte[] buf = apdu.getBuffer(); short len = apdu.setIncomingAndReceive();
        if (len != CardRepository.EMP_INFO_MAX) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (repository.isIdSet()) {
            security.encryptData(buf, ISO7816.OFFSET_CDATA, CardRepository.EMP_ID_LEN, tempCompBuffer, (short) 0);
            byte[] currentEncryptedInfo = repository.getEmpInfoBuffer();
            if (Util.arrayCompare(tempCompBuffer, (short) 0, currentEncryptedInfo, CardRepository.EMP_ID_OFFSET, CardRepository.EMP_ID_LEN) != 0)
                ISOException.throwIt(SW_EMP_ID_LOCKED);
        }
        security.encryptData(buf, ISO7816.OFFSET_CDATA, len, buf, ISO7816.OFFSET_CDATA);
        repository.setEmpInfo(buf, ISO7816.OFFSET_CDATA, len);
    }

    private void handleGetBalance(APDU apdu) {
        byte[] buf = apdu.getBuffer(); 
        byte[] encryptedBal = repository.getBalanceBuffer();
        Util.arrayFillNonAtomic(tempCompBuffer, (short)0, (short)16, (byte)0);
        if (Util.arrayCompare(encryptedBal, (short)0, tempCompBuffer, (short)0, (short)16) == 0) 
        { 
        	Util.arrayFillNonAtomic(buf, (short)0, (short)4, (byte)0); 
        	apdu.setOutgoingAndSend((short) 0, (short) 4); return; 
        }
        security.decryptData(encryptedBal, (short)0, (short)16, tempBalance, (short)0);
        Util.arrayCopyNonAtomic(tempBalance, (short) 12, buf, (short) 0, (short) 4); 
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }
    private void handleTopUp(APDU apdu) {
        byte[] buf = apdu.getBuffer(); short len = apdu.setIncomingAndReceive(); 
        if (len != 4) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte[] encryptedBal = repository.getBalanceBuffer();
        Util.arrayFillNonAtomic(tempCompBuffer, (short)0, (short)16, (byte)0);
        if (Util.arrayCompare(encryptedBal, (short)0, tempCompBuffer, (short)0, (short)16) == 0) 
        	Util.arrayFillNonAtomic(tempBalance, (short)0, (short)16, (byte)0);
        else security.decryptData(encryptedBal, (short)0, (short)16, tempBalance, (short)0);
        repository.addUnsigned32(tempBalance, (short) 12, buf, ISO7816.OFFSET_CDATA);
        security.encryptData(tempBalance, (short)0, (short)16, tempBalance, (short)0); 
        repository.setBalance(tempBalance, (short)0);
    }
    private void handlePay(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();
    
		// Amount(4) + Time(4) + UN(4) = 12 bytes
		if (len != 12) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    
		if (!security.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		// Decrypt -> Check -> Tr tin)
		byte[] encryptedBal = repository.getBalanceBuffer();

		Util.arrayFillNonAtomic(tempCompBuffer, (short)0, (short)64, (byte)0); // Clear trc
		if (Util.arrayCompare(encryptedBal, (short)0, tempCompBuffer, (short)0, (short)16) == 0) 
			ISOException.throwIt((short) 0x6A84); // Not enough money
        
		security.decryptData(encryptedBal, (short)0, (short)16, tempBalance, (short)0);
    
		// tempBalance (offset 12) < Amount (Input offset CDATA)
		if (repository.compareUnsigned32(tempBalance, (short)12, buf, ISO7816.OFFSET_CDATA) < 0) 
			ISOException.throwIt((short) 0x6A84);
        
		// Tru tien
		repository.subUnsigned32(tempBalance, (short) 12, buf, ISO7816.OFFSET_CDATA);
    
		// Tich iem ( Amount chia 10000)
		short lowAmount = Util.getShort(buf, (short) (ISO7816.OFFSET_CDATA + 2)); 
		if (lowAmount > 0) repository.addPoint((byte)(lowAmount / 10000));
    
		// save new bal (Encrypt -> Save)
		security.encryptData(tempBalance, (short)0, (short)16, tempBalance, (short)0); 
		repository.setBalance(tempBalance, (short)0);

		// [ID (16)] [Amount (4)] [Time (4)] [UN (4)]
		short off = 0;
    
		byte[] encInfo = repository.getEmpInfoBuffer();
		// Decrypt 16 byte (ID) vào tempCompBuffer ti offset 0
		security.decryptData(encInfo, (short)0, (short)16, tempCompBuffer, (short)0); 
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
         byte[] buf = apdu.getBuffer(); short len = apdu.setIncomingAndReceive(); if (len != 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
         security.encryptData(buf, ISO7816.OFFSET_CDATA, (short) 32, buf, ISO7816.OFFSET_CDATA); repository.addLog(buf, ISO7816.OFFSET_CDATA);
    }
    private void handleReadLogs(APDU apdu) {
        byte[] logs = repository.getLogBuffer(); short total = repository.getTotalLogLen(); 
        if (logs[0] == 0) { Util.arrayFillNonAtomic(apdu.getBuffer(), (short)0, total, (byte)0); apdu.setOutgoingAndSend((short)0, total); return; }
        Util.arrayCopyNonAtomic(logs, (short)0, apdu.getBuffer(), (short)0, total);
        security.decryptData(apdu.getBuffer(), (short)0, total, apdu.getBuffer(), (short)0); apdu.setOutgoingAndSend((short)0, total);
    }
}