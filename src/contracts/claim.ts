import { assert } from 'console'
import {
    bsv,
    hash160,
    method,
    prop,
    PubKey,
    PubKeyHash,
    Sig,
    SmartContract,
    toHex,
    UTXO,
} from 'scrypt-ts'

export class Claim extends SmartContract {
    // @prop(true)
    @prop()
    winner: PubKeyHash

    // @prop(true)
    @prop()
    open: boolean

    constructor(open: boolean, winner: PubKeyHash) {
        super(open, winner)
        this.winner = winner
        this.open = open
    }

    @method()
    public claim(sig: Sig, pubKey: PubKey) {
        assert(!this.open, "can't claim open bounty")
        assert(
            hash160(pubKey) == this.winner,
            'public key was not selected as winner'
        )
        assert(this.checkSig(sig, pubKey), 'signature check failed')
    }

    getDeployTx(utxos: UTXO[], initBalance: number): bsv.Transaction {
        const tx = new bsv.Transaction().from(utxos).addOutput(
            new bsv.Transaction.Output({
                script: this.lockingScript,
                satoshis: initBalance,
            })
        )
        this.lockTo = { tx, outputIndex: 0 }
        return tx
    }

    getCallTx(
        pubKey: bsv.PublicKey,
        privateKey: bsv.PrivateKey,
        prevTx: bsv.Transaction
    ): bsv.Transaction {
        const inputIndex = 0
        return new bsv.Transaction().addInputFromPrevTx(prevTx).setInputScript(
            {
                inputIndex,
                privateKey,
            },
            (tx) => {
                const sig = tx.getSignature(inputIndex)
                this.unlockFrom = { tx, inputIndex }
                return this.getUnlockingScript((self) => {
                    self.claim(Sig(sig as string), PubKey(toHex(pubKey)))
                })
            }
        )
    }
}
