package employee_card;

import javacard.framework.*;

public class CardRepository {

    // Config
    public static final short EMP_INFO_MAX = 128;
    public static final byte EMP_ID_LEN = 16;
    public static final short EMP_ID_OFFSET = 0;
    
    // Log & Balance Config
    private static final byte MAX_LOGS = 8;
    private static final byte LOG_SIZE = 32; 
    private static final short U32_LEN = 4;
    private static final short BALANCE_STORAGE_LEN = 16;
    
    // Data Store (EEPROM)
    private byte[] empInfo;
    private byte[] balance;
    private short points;
    private byte[] logs;
    private byte logIndex;
    
    // ( XA BIN AVATAR  CHUYN SANG CLASS Avatar.java)

    public CardRepository() {
        empInfo = new byte[EMP_INFO_MAX];
        balance = new byte[BALANCE_STORAGE_LEN]; 
        logs = new byte[(short) (MAX_LOGS * LOG_SIZE)];
        points = 0;
        logIndex = 0;
    }

    public boolean isIdSet() {
        for (short i = 0; i < EMP_ID_LEN; i++) {
            if (empInfo[(short) (EMP_ID_OFFSET + i)] != 0) return true;
        }
        return false;
    }

    public void setEmpInfo(byte[] src, short srcOff, short len) {
        JCSystem.beginTransaction();
        Util.arrayCopy(src, srcOff, empInfo, (short) 0, len);
        if (len < EMP_INFO_MAX) {
            Util.arrayFillNonAtomic(empInfo, len, (short) (EMP_INFO_MAX - len), (byte) 0);
        }
        JCSystem.commitTransaction();
    }

    public byte[] getEmpInfoBuffer() { return empInfo; }

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