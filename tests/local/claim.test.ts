import { Claim } from '../../src/contracts/claim'
import { expect } from 'chai'
import { dummyUTXO, newTx, inputSatoshis } from './util/txHelper'
import { bsv, hash160, PubKey, PubKeyHash, Sig, signTx, toHex } from 'scrypt-ts'

describe('Test `Claim` SmartContract', () => {
    before(async () => {
        await Claim.compile()
    })

    it('should pass with valid winner claim', async () => {
        await validWinnerTest()
    })

    it('should fail with invalid winner claim', async () => {
        await invalidWinnerTest()
    })

    // it('should fail with invalid signature', async () => {
    //     await invalidSignatureTest();
    // })

    // it('should fail when bounty still open', async () => {
    //     await bountyOpenTest();
    // })
})

async function validWinnerTest() {
    //constructor arguments
    const inputIndex = 0
    const privateKey = bsv.PrivateKey.fromRandom('testnet')
    const publicKey = bsv.PublicKey.fromPrivateKey(privateKey)
    const pubKey = PubKey(toHex(publicKey))
    const PKH: PubKeyHash = PubKeyHash(hash160(pubKey))
    // new instance
    const instance = new Claim(false, PKH)
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

async function invalidWinnerTest() {
    //constructor arguments
    const inputIndex = 0
    const privateKey = bsv.PrivateKey.fromRandom('testnet')
    const publicKey = bsv.PublicKey.fromPrivateKey(privateKey)
    const pubKey = PubKey(toHex(publicKey))
    const PKH: PubKeyHash = PubKeyHash(hash160(pubKey))
    // new instance
    const instance = new Claim(false, PKH)
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
        const sig = signTx(
            tx,
            invalidPrivateKey,
            instance.lockingScript,
            inputSatoshis
        )
        instance.claim(Sig(toHex(sig)), invalidPubKey)
    }).to.throw(/Execution failed/)
}
