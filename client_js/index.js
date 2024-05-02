import nacl from './nacl.min.cjs';
import {HandshakeMsg, HandshakeTyp_ClientHello, HandshakeTyp_ServerHello} from './handshake.js';
import {Record, RecordTypeHandshake, readRecord} from './record.js';
import {bytesToHexString, hexStringToBytes} from "./util.js";
import cryptoJs from 'crypto-js';

const {algo, enc, PBKDF2} = cryptoJs

const DHE_X25519_WITH_XSALSA20_POLY1305 = 0xca;

const ticketKdf = enc.Utf8.parse('ticket kdf')
const masterKdf = enc.Utf8.parse('master kdf')

export default async function wdals(host) {
    let box = nacl.box

    let {secretKey, publicKey} = box.keyPair() // 客户端临时生成公、私密钥对
    let nowTs = Math.round(new Date().getTime() / 1000),
        clientHello = new HandshakeMsg(nowTs, publicKey, DHE_X25519_WITH_XSALSA20_POLY1305, nacl.randomBytes(32));
    let record = new Record(RecordTypeHandshake, clientHello.marshal(HandshakeTyp_ClientHello))

    let hasher = algo.SHA256.create();
    hasher.update(enc.Hex.parse(bytesToHexString(record.data)));

    let url = host + '/wdals?hello=' + enc.Hex.parse(bytesToHexString(record.marshal())).toString(enc.Base64url)

    // todo 0. sendClientHello
    let req = await fetch(url)
    if (req.status !== 200) throw new Error(req.statusText)
    let rsp = await req.arrayBuffer()
    let recv_data = new Uint8Array(rsp)

    // todo 1. readServerHello
    let {pos, record: record1} = readRecord(recv_data);
    if (record1.typ !== RecordTypeHandshake) throw new Error('data corrupted')
    recv_data = recv_data.slice(pos)
    hasher.update(enc.Hex.parse(bytesToHexString(record1.data)));

    let serverHello = HandshakeMsg.unMarshal(record1.data, HandshakeTyp_ServerHello);
    if (serverHello.cipherSuite !== DHE_X25519_WITH_XSALSA20_POLY1305) throw new Error('cipher not support')

    // todo 2. keys kdf
    let preSharedKey = bytesToHexString(nacl.scalarMult(secretKey, serverHello.cipherKey));
    let sum = hasher.finalize();
    let masterKey = PBKDF2(enc.Hex.parse(preSharedKey), masterKdf.clone().concat(sum),
        {keySize: 192 / 32, hasher: algo.SHA256}) // 192=24KeyLen*8
    console.debug('client', 'masterKey', masterKey.toString())

    let ticketKey = PBKDF2(enc.Hex.parse(preSharedKey), ticketKdf.clone().concat(sum),
        {keySize: 256 / 32, hasher: algo.SHA256}) // 256=32keyLen*8
    console.debug('client', 'ticketKey', ticketKey.toString())

    // todo 3. readNewSessionTicket
    let {record: record2} = readRecord(recv_data);
    let nonce = hexStringToBytes(masterKey.toString())
    nonce[8] = record2.typ
    nonce[9] = record2.version

    let ticketData = box.open(record2.data, nonce, serverHello.cipherKey, secretKey);
    let ticketExpire = new DataView(ticketData.slice(0, 4).buffer).getUint32(0);
    let sessionTicket = enc.Hex.parse(bytesToHexString(ticketData.slice(4)))
    return {
        ticketKey: ticketKey.toString(enc.Base64),
        ticketExpire: ticketExpire,
        sessionTicket: sessionTicket.toString(enc.Base64)
    }
}