import {uint16ToSliceBigEndian} from './util.js';

export const RecordTypeHandshake = 0x13, RecordTypeApplicationData = 0x14;

export class Record {
    static ProtocolAesGcm = 0b01
    static ProtocolXsalsa20Poly1305 = 0b10

    constructor(typ = 0, data = new Uint8Array(0)) {
        this.typ = typ
        this.version = Record.ProtocolXsalsa20Poly1305
        this.length = data.length
        this.data = data
    }

    marshal() {
        let {version, data, typ, length} = this;
        let dataLen = uint16ToSliceBigEndian(length);

        let arr = new Uint8Array(2 + dataLen.length + length); // total length
        arr.set([typ, version, ...dataLen, ...data])
        return arr
    }
}

export function readRecord(data) {
    if (!data || data.length < 4) {
        throw new Error('data corrupted')
    }

    let record
    if (data[1] === Record.ProtocolXsalsa20Poly1305) {
        record = new Record()
    } else {
        throw new Error('this client not support') //
    }
    record.typ = data[0]
    record.version = data[1]
    let pos = 2

    let dv = new DataView(data.buffer)
    record.length = dv.getUint16(pos);
    pos += 2

    record.data = data.slice(pos, pos + record.length)
    pos += record.length

    return {pos, record}
}
