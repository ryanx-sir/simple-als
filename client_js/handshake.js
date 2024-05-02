import {uint32ToSliceBigEndian, uint16ToSliceBigEndian} from './util.js';


const HandshakeTyp_ClientHello = 0b01;
const HandshakeTyp_ServerHello = 0b10;

export {
    HandshakeTyp_ClientHello, HandshakeTyp_ServerHello,
}

export class HandshakeMsg {
    constructor(ts = 0, cipherKey, cipherSuite, nonce) {
        this.ts_ = ts
        this.cipherKey = cipherKey
        this.cipherSuite = cipherSuite
        this.nonce = nonce
    }

    static unMarshal(data, handshakeTyp) {
        if (!data || data.length < 40) {
            throw new Error('data corrupted')
        }
        if (data[0] !== handshakeTyp) {
            throw new Error('data corrupted')
        }
        let dv = new DataView(data.buffer)
        let msg = new HandshakeMsg()

        let pos = 1
        msg.nonce = data.slice(pos, pos + 32)
        pos += 32

        msg.ts_ = dv.getUint32(pos)
        pos += 4

        msg.cipherSuite = dv.getUint8(pos)
        pos++

        let keyLen = dv.getUint16(pos)
        pos += 2

        msg.cipherKey = data.slice(pos, pos + keyLen)
        return msg
    }

    marshal(handshakeTyp) {
        let {nonce, ts_, cipherSuite, cipherKey} = this
        let ts = uint32ToSliceBigEndian(ts_),
            keyLen = uint16ToSliceBigEndian(cipherKey.length);

        let arr = new Uint8Array(2 + nonce.length + ts.length + keyLen.length + cipherKey.length);
        arr.set([handshakeTyp, ...nonce, ...ts, cipherSuite, ...keyLen, ...cipherKey])
        return arr
    }
}
