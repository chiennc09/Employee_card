package employee_card;

import javacard.framework.*;

public class CardRepository {

    //CONFIG SIZES
    public static final byte LEN_ID   = 16;
    public static final byte LEN_NAME = 48;
    public static final byte LEN_DOB  = 16;
    public static final byte LEN_DEPT = 32;
    public static final byte LEN_POS  = 32; 
    
    public static final short TOTAL_INFO_SIZE = (short)(LEN_ID + LEN_NAME + LEN_DOB + LEN_DEPT + LEN_POS);
    
    // Log & Balance Config
    private static final byte MAX_LOGS = 8;
    private static final byte LOG_SIZE = 32; 
    private static final short U32_LEN = 4;
    private static final short BALANCE_STORAGE_LEN = 16;
    
    // Data Store (EEPROM)
    private byte[] encId;
    private byte[] encName;
    private byte[] encDob;
    private byte[] encDept;
    private byte[] encPos;
    private byte[] balance;
    private short points;
    private byte[] logs;
    private byte logIndex;

    public CardRepository() {
        encId = new byte[LEN_ID];
        encName = new byte[LEN_NAME];
        encDob = new byte[LEN_DOB];
        encDept = new byte[LEN_DEPT];
        encPos = new byte[LEN_POS];
        balance = new byte[BALANCE_STORAGE_LEN]; 
        logs = new byte[(short) (MAX_LOGS * LOG_SIZE)];
        points = 0;
        logIndex = 0;
    }

    public boolean isIdSet() {
        for (short i = 0; i < LEN_ID; i++) {
            if (encId[i] != 0) return true;
        }
        return false;
    }

    // --- SETTERS ---
    public void setEncryptedId(byte[] src, short off) {
        JCSystem.beginTransaction();
        Util.arrayCopy(src, off, encId, (short)0, LEN_ID);
        JCSystem.commitTransaction();
    }
    
    public void setEncryptedName(byte[] src, short off) {
        JCSystem.beginTransaction();
        Util.arrayCopy(src, off, encName, (short)0, LEN_NAME);
        JCSystem.commitTransaction();
    }

    public void setEncryptedDob(byte[] src, short off) {
        JCSystem.beginTransaction();
        Util.arrayCopy(src, off, encDob, (short)0, LEN_DOB);
        JCSystem.commitTransaction();
    }

    public void setEncryptedDept(byte[] src, short off) {
        JCSystem.beginTransaction();
        Util.arrayCopy(src, off, encDept, (short)0, LEN_DEPT);
        JCSystem.commitTransaction();
    }

    public void setEncryptedPos(byte[] src, short off) {
        JCSystem.beginTransaction();
        Util.arrayCopy(src, off, encPos, (short)0, LEN_POS);
        JCSystem.commitTransaction();
    }

    // --- GETTERS ---
    public byte[] getEncryptedId() { return encId; }
    public byte[] getEncryptedName() { return encName; }
    public byte[] getEncryptedDob() { return encDob; }
    public byte[] getEncryptedDept() { return encDept; }
    public byte[] getEncryptedPos() { return encPos; }

    public void addLog(byte[] src, short srcOff) {
        short base = (short) (logIndex * LOG_SIZE);
        JCSystem.beginTransaction();
        Util.arrayFillNonAtomic(logs, base, LOG_SIZE, (byte) 0x00);
        Util.arrayCopy(src, srcOff, logs, base, LOG_SIZE);
        logIndex++;
        if (logIndex >= MAX_LOGS) logIndex = 0;
        JCSystem.commitTransaction();
    }
    
    public byte[] getLogBuffer() { return logs; }
    public short getTotalLogLen() { return (short) (MAX_LOGS * LOG_SIZE); }

    public void addPoint(byte p) { points += p; }
    public short getPoints() { return points; }
    
    public byte[] getBalanceBuffer() { return balance; }
    public void setBalance(byte[] src, short off) {
        JCSystem.beginTransaction();
        Util.arrayCopy(src, off, balance, (short) 0, BALANCE_STORAGE_LEN);
        JCSystem.commitTransaction();
    }

    public void addUnsigned32(byte[] acc, short accOff, byte[] add, short addOff) {
        short carry = 0;
        for (short i = (short) (U32_LEN - 1); i >= 0; i--) {
            short sum = (short) ((short) (acc[(short)(accOff+i)] & 0xFF) + (short) (add[(short)(addOff+i)] & 0xFF) + carry);
            acc[(short)(accOff+i)] = (byte) sum;
            carry = (short) ((sum >> 8) & 0x01);
        }
    }
    
    public void subUnsigned32(byte[] acc, short accOff, byte[] sub, short subOff) {
        short borrow = 0;
        for (short i = (short) (U32_LEN - 1); i >= 0; i--) {
            short diff = (short) ((short) (acc[(short)(accOff+i)] & 0xFF) - (short) (sub[(short)(subOff+i)] & 0xFF) - borrow);
            if (diff < 0) { diff += 256; borrow = 1; } else { borrow = 0; }
            acc[(short)(accOff+i)] = (byte) diff;
        }
    }
    
    public byte compareUnsigned32(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < U32_LEN; i++) {
            short va = (short) (a[(short) (aOff + i)] & 0xFF);
            short vb = (short) (b[(short) (bOff + i)] & 0xFF);
            if (va < vb) return -1;
            if (va > vb) return 1;
        }
        return 0;
    }
}