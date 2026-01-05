package employee_card;

import javacard.framework.*;

public class Avatar {
    
    private byte[] data;
    private short size;
    private short maxSize;

    public Avatar(short sizeLimit) {
        // Cap phát 8192 bytes ngay lp tc (Pre-allocation)
        this.maxSize = sizeLimit;
        this.data = new byte[maxSize];
        this.size = 0;
    }

    public void setData(byte[] buffer, short bufOffset, short chunkOffset, short chunkLength) {
        // Kim tra tràn b nh
        if ((short)(chunkOffset + chunkLength) > maxSize) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        // Copy du lieu vào mang
        Util.arrayCopyNonAtomic(buffer, bufOffset, data, chunkOffset, chunkLength);
        
        // Cap nhat kích thuoc thuc te
        short newEnd = (short) (chunkOffset + chunkLength);
        if (newEnd > size) {
            size = newEnd;
        }
    }

    public byte[] getData() {
        return data;
    }

    public short getSize() {
        return size;
    }
}