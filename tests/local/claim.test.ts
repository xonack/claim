import { Claim } from '../../src/contracts/claim'
import { expect } from 'chai'
import { dummyUTXO, newTx, inputIndex, inputSatoshis } from './util/txHelper'
import {
    bsv,
    hash160,
    PubKey,
    PubKeyHash,
    Ripemd160,
    Sig,
    signTx,
    toByteString,
    toHex,
} from 'scrypt-ts'

const privateKey = bsv.PrivateKey.fromRandom('testnet')
const publicKey = privateKey.publicKey
const pubKey = PubKey(toHex(publicKey))
const pkh: PubKeyHash = PubKeyHash(hash160(pubKey))

describe('Test `Claim` SmartContract', () => {
    before(async () => {
        await Claim.compile()
    })

    // it('should pass with valid winner claim', async () => {
    //     await validWinnerTest()
    // })

    it('should fail with invalid public key', async () => {
        await invalidPubKeyTest()
    })

    // it('should fail with invalid signature', async () => {
    //     await invalidSignatureTest();
    // })

    // it('should fail with invalid public key and corresponding signature', async () => {
    //     await invalidSigAndPubKeyTest();
    // })

    // it('should fail when bounty still open', async () => {
    //     await bountyOpenTest();
    // })
})

async function validWinnerTest() {
    // new instance
    const instance = new Claim(false, pkh)
    // unlockFrom for stateful contract
    dummyUTXO.script = instance.lockingScript.toHex()
    const utxos = [dummyUTXO]
    const tx = newTx(utxos)
    instance.unlockFrom = { tx, inputIndex }
    // instance.verify
    const result = instance.verify((self) => {
        const sig = signTx(tx, privateKey, self.lockingScript, inputSatoshis)
        self.claim(Sig(toHex(sig)), pubKey)
    })
    // expect result
    expect(result.success, result.error).to.be.true
}

async function invalidPubKeyTest() {
    // new instance
    const instance = new Claim(false, pkh)
    // unlockFrom for stateful contract
    dummyUTXO.script = instance.lockingScript.toHex()
    const utxos = [dummyUTXO]
    const tx = newTx(utxos)
    instance.unlockFrom = { tx, inputIndex }
    // expect assertion error
    const invalidPrivateKey = bsv.PrivateKey.fromRandom('testnet')
    const invalidPublicKey = bsv.PublicKey.fromPrivateKey(invalidPrivateKey)
    const invalidPubKey = PubKey(toHex(invalidPublicKey))
    expect(() => {
        instance.verify(() => {
            const sig = signTx(
                tx,
                privateKey,
                instance.lockingScript,
                inputSatoshis
            )
            instance.claim(Sig(toHex(sig)), invalidPubKey)
        })
    }).to.throw(/Execution failed/)
}

async function invalidSignatureTest() {
    // new instance
    const instance = new Claim(false, pkh)
    // unlockFrom for stateful contract
    dummyUTXO.script = instance.lockingScript.toHex()
    const utxos = [dummyUTXO]
    const tx = newTx(utxos)
    instance.unlockFrom = { tx, inputIndex }
    // expect assertion error
    const invalidPrivateKey = bsv.PrivateKey.fromRandom('testnet')
    expect(() => {
        instance.verify(() => {
            const invalidSig = signTx(
                tx,
                invalidPrivateKey,
                instance.lockingScript,
                inputSatoshis
            )
            instance.claim(Sig(toHex(invalidSig)), pubKey)
        })
    }).to.throw(/Execution failed/)
}

async function invalidSigAndPubKeyTest() {
    // new instance
    const instance = new Claim(false, pkh)
    // unlockFrom for stateful contract
    dummyUTXO.script = instance.lockingScript.toHex()
    const utxos = [dummyUTXO]
    const tx = newTx(utxos)
    instance.unlockFrom = { tx, inputIndex }
    // expect assertion error
    const invalidPrivateKey = bsv.PrivateKey.fromRandom('testnet')
    const invalidPublicKey = bsv.PublicKey.fromPrivateKey(invalidPrivateKey)
    const invalidPubKey = PubKey(toHex(invalidPublicKey))
    expect(() => {
        instance.verify(() => {
            const invalidSig = signTx(
                tx,
                invalidPrivateKey,
                instance.lockingScript,
                inputSatoshis
            )
            instance.claim(Sig(toHex(invalidSig)), invalidPubKey)
        })
    }).to.throw(/Execution failed/)
}

async function bountyOpenTest() {
    // new instance
    const instance = new Claim(true, Ripemd160(toByteString('00')))
    // unlockFrom for stateful contract
    dummyUTXO.script = instance.lockingScript.toHex()
    const utxos = [dummyUTXO]
    const tx = newTx(utxos)
    instance.unlockFrom = { tx, inputIndex }
    // expect assertion error
    expect(() => {
        instance.verify(() => {
            const sig = signTx(
                tx,
                privateKey,
                instance.lockingScript,
                inputSatoshis
            )
            instance.claim(Sig(toHex(sig)), pubKey)
        })
    }).to.throw(/Execution failed/)
}
