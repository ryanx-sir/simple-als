export function uint32ToSliceBigEndian(val) {
    let ab = new ArrayBuffer(4)
    let dv = new DataView(ab)
    dv.setUint32(0, val)
    return new Uint8Array(ab)
}

export function uint16ToSliceBigEndian(val) {
    let ab = new ArrayBuffer(2)
    let dv = new DataView(ab)
    dv.setUint16(0, val)
    return new Uint8Array(ab)
}

export function bytesToHexString(bytes) {
    return bytes.reduce((str, a) => str + a.toString(16).padStart(2, '0'), '')
}

export function hexStringToBytes(hexString) {
    return Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}