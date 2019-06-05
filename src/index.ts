import * as bitcoin from "bitcoin-ts-cashcontracts"
import * as cashcontracts from "cashcontracts-wasm"
import { List, Map, Set } from "immutable"
import * as Immutable from "immutable"
import { Base64 } from 'js-base64'
import { BigNumber } from 'bignumber.js'

export type TokenId = string
export type UtxoId = string

export const DUST_AMOUNT = new BigNumber('546')
export const MAX_INT = new BigNumber('2').pow('31')

export const ready = cashcontracts.ready

const EMPTY_CASH_ADDR = 'bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603'
const EMPTY_SLP_ADDR = 'simpleledger:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9gud9630'
const SLP_B64 = "U0xQAA=="  // base64.b64encode(b'SLP\0') == b'U0xQAA=='

function bufferToHex(buffer: Uint8Array): string {
    let s = '', h = '0123456789ABCDEF';
    buffer.forEach((v) => { s += h[v >> 4] + h[v & 15]; });
    return s;
}

function hexToBuffer(hex: string): Uint8Array {
    if (typeof hex !== 'string') {
      throw new TypeError('Expected input to be a string')
    }
    if ((hex.length % 2) !== 0) {
      throw new RangeError('Expected string to be an even number of characters')
    }
    var array = new Uint8Array(hex.length / 2)
    for (var i = 0; i < hex.length; i += 2) {
      array[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    return array
}

function keyError(key: any): never {
    return new Proxy({}, { get(target, name, receiver) {
        throw "Key error: " + key
    }}) as never
}

function err<T>(f: () => T): T {
    try {
        return f()
    } catch (e) {
        console.error(e)
        throw e
    }
}

export type TxDirection = 'incoming' | 'outgoing' | 'update'
export type TxKind = 'SLP' | 'default'
export interface TxEvent {
    direction: TxDirection
    nonTokenDelta: BigNumber
    tokenDelta: Map<TokenId, BigNumber>
}

export interface Endpoint {
    fetchTokenUtxos(slpAddress: string): Promise<List<SLPUtxoEntryRemote>>
    fetchUtxos(address: string): Promise<List<UtxoEntry>>
    fetchTokenDetails(tokenIds: List<TokenId>): Promise<Map<TokenId, TokenDetails>>
}

class EndpointDefault implements Endpoint {
    async fetchTokenUtxos(slpAddress: string): Promise<List<SLPUtxoEntryRemote>> {
        const query = {
            "v": 3,
            "q": {
                "db": ["x"],
                "find": {
                    "address": slpAddress,
                },
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const response = await fetch("https://slpdb.fountainhead.cash/q/" + queryBase64)
        const utxosJson: {x: SLPUtxoEntryRemote[]} = await response.json()
        return List(utxosJson.x)
    }

    async fetchUtxos(address: string): Promise<List<UtxoEntry>> {
        const utxosJson: {utxos: UtxoEntryRemote[]} = await (await fetch("https://rest.bitcoin.com/v2/address/utxo/" + address)).json()
        return List(utxosJson.utxos).map(utxo => ({
            txid: utxo.txid,
            vout: utxo.vout,
            satoshis: new BigNumber(utxo.satoshis),
        }))
    }

    async fetchTokenDetails(tokenIds: List<string>): Promise<Map<string, TokenDetails>> {
        const tokenDetails: TokenDetails[] = await (await fetch("https://rest.bitcoin.com/v2/slp/list", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({tokenIds: tokenIds.toArray()}),
        })).json()
        if (Wallet.debug)
            console.log(tokenDetails)
        return Map(tokenDetails.map(details => [details.id, details] as [string, TokenDetails]))
    }
}

class TokenDetailStore {
    private _tokenDetails: Map<TokenId, TokenDetails> = Map()
    private _endpoint: Endpoint

    public constructor(endpoint: Endpoint) {
        this._endpoint = endpoint
    }

    public async detailsForIds(tokenIds: List<string>): Promise<Map<string, TokenDetails>> {
        const newTokenIds = tokenIds.filter(tokenId => !this._tokenDetails.has(tokenId)).toList()
        if (newTokenIds.size > 0) {
            const newTokenDetails = await this._endpoint.fetchTokenDetails(newTokenIds)
            this._tokenDetails = Immutable.merge(this._tokenDetails, newTokenDetails)
        }
        return this._tokenDetails.filter((_, tokenId) => tokenIds.contains(tokenId))
    }

    public tokenDetails(): Map<TokenId, TokenDetails> {
        return this._tokenDetails
    }
}

class Utxos {
    private _address: string
    private _slpAddress: string
    private _endpoint: Endpoint
    private _tokenDetailStore: TokenDetailStore
    private _tokenUtxoIds: Set<UtxoId> = Set()
    private _tokenUtxos: Map<TokenId, Map<UtxoId, SLPUtxoEntry>> = Map()
    private _nonTokenUtxos: Map<UtxoId, UtxoEntry> = Map()

    public constructor(address: string, slpAddress: string, endpoint: Endpoint, tokenDetailsStore: TokenDetailStore) {
        this._endpoint = endpoint
        this._tokenDetailStore = tokenDetailsStore
        this._address = address
        this._slpAddress = slpAddress
    }

    private static calculateBaseToken(utxosJson: List<SLPUtxoEntryRemote>,
                                      details: Map<string, TokenDetails>) {
        return utxosJson.map(utxo => {
            const amountFactor = new BigNumber('10').pow(
                details.get(
                    utxo.tokenDetails.tokenIdHex,
                    keyError(utxo.tokenDetails.tokenIdHex)
                ).decimals,
            )
            return {
                ...utxo,
                slpBaseAmount: new BigNumber(utxo.slpAmount).times(amountFactor),
                amountFactor: amountFactor,
            } as SLPUtxoEntry
        })
    }

    private static getUtxoId(utxo: {txid: string, vout: number}): UtxoId {
        return utxo.txid + ':' + utxo.vout
    }

    public async updateTokens(): Promise<void> {
        const utxosJson = await this._endpoint.fetchTokenUtxos(this._slpAddress)
        const tokenIds = Set(utxosJson.map(utxo => utxo.tokenDetails.tokenIdHex))
        const tokenDetails = await this._tokenDetailStore.detailsForIds(tokenIds.toList())
        const utxos = Utxos.calculateBaseToken(utxosJson, tokenDetails)
        const utxosByToken = utxos
            .groupBy((entry) => entry.tokenDetails.tokenIdHex)
            .map(utxos => utxos.toList())
            .toMap()
        this._tokenUtxos = utxosByToken.map(utxos => Map(utxos.map(utxo => [
            Utxos.getUtxoId(utxo),
            utxo,
        ] as [string, SLPUtxoEntry])))
        this._tokenUtxoIds = utxosJson.map(Utxos.getUtxoId).toSet()
    }

    public async update(): Promise<void> {
        await this.updateTokens()
        const utxos = await this._endpoint.fetchUtxos(this._address)
        this._nonTokenUtxos = Map(utxos.map(utxo => [Utxos.getUtxoId(utxo), utxo]))
            .filter((_, utxoId) => !this._tokenUtxoIds.contains(utxoId))
    }

    public tokenIds(): List<TokenId> {
        return this._tokenUtxos.keySeq().toList()
    }

    public tokenUtxos(): Map<TokenId, Map<UtxoId, SLPUtxoEntry>> {
        return this._tokenUtxos
    }

    public nonTokenUtxos(): Map<UtxoId, UtxoEntry> {
        return this._nonTokenUtxos
    }

    public removeTokenUtxo(tokenId: TokenId, utxo: {txid: string, vout: number}) {
        const utxoId = Utxos.getUtxoId(utxo)
        if (this._nonTokenUtxos.has(utxoId)) {
            this._nonTokenUtxos = this._nonTokenUtxos.remove(utxoId)
            return
        }
        const tokenUtxos = this._tokenUtxos.get(tokenId, keyError(tokenId)).remove(utxoId)
        if (tokenUtxos.size == 0)
            this._tokenUtxos = this._tokenUtxos.remove(tokenId)
        else
            this._tokenUtxos = this._tokenUtxos.set(tokenId, tokenUtxos)
        this._tokenUtxoIds = this._tokenUtxoIds.remove(utxoId)
    }

    public removeNonTokenUtxo(utxo: {txid: string, vout: number}) {
        const utxoId = Utxos.getUtxoId(utxo)
        this._nonTokenUtxos = this._nonTokenUtxos.remove(utxoId)
    }

    public async addTokenUtxo(utxoJson: SLPUtxoEntryRemote) {
        const tokenDetails = await this._tokenDetailStore.detailsForIds(List.of(utxoJson.tokenDetails.tokenIdHex))
        const utxo = Utxos.calculateBaseToken(List.of(utxoJson), tokenDetails).get(0, keyError(0))
        const utxoId = Utxos.getUtxoId(utxo)
        const tokenUtxos = this._tokenUtxos.get(utxo.tokenDetails.tokenIdHex, Map<string, SLPUtxoEntry>())
        this._tokenUtxos = this._tokenUtxos.set(utxo.tokenDetails.tokenIdHex, tokenUtxos.set(utxoId, utxo))
        this._tokenUtxoIds = this._tokenUtxoIds.add(utxoId)
    }

    public addNonTokenUtxo(utxo: UtxoEntry) {
        this._nonTokenUtxos = this._nonTokenUtxos.set(Utxos.getUtxoId(utxo), utxo)
    }
}

export class Wallet {
    public static debug: boolean
    private _curve: bitcoin.Secp256k1
    private _secret: Uint8Array
    private _pubkey: Uint8Array
    private _address: cashcontracts.Address
    private _slpAddress: cashcontracts.Address
    private _addressBase: string
    private _wallet: cashcontracts.Wallet
    private _utxos: Utxos
    private _tokenDetailStore: TokenDetailStore
    private _sha256: bitcoin.Sha256
    private _isWaitingToUpdate: boolean = false
    private _isUpdated: boolean = false
    private _isInitialized: boolean = false
    
    private _receivedTxListeners: ((direction: TxEvent) => void)[] = []

    private constructor(curve: bitcoin.Secp256k1,
                        secret: Uint8Array,
                        pubkey: Uint8Array,
                        wallet: cashcontracts.Wallet,
                        address: cashcontracts.Address,
                        slpAddress: cashcontracts.Address,
                        addressBase: string,
                        utxos: Utxos,
                        tokenDetailStore: TokenDetailStore) {
        this._curve = curve
        this._secret = secret
        this._pubkey = pubkey
        this._address = address
        this._slpAddress = slpAddress
        this._addressBase = addressBase
        this._wallet = wallet
        this._utxos = utxos
        this._tokenDetailStore = tokenDetailStore
        this.registerEvents()
    }

    private registerEvents() {
        this.listenToNonTokenIncoming()
        this.listenToNonTokenOutgoing()
        this.listenToTokenIncoming()
        this.listenToTokenOutgoing()
    }

    private listenToNonTokenIncoming(): EventSource {
        const query = {
            "v": 3,
            "q": {
                "find": {
                    "in": {"$not": {"$elemMatch": {"e.a": this._addressBase}}},
                    "out.e.a": this._addressBase,
                    "out.b1": {"$ne": SLP_B64},
                },
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const source = new EventSource("https://bitsocket.fountainhead.cash/s/" + queryBase64)
        source.onmessage = (msg) => this.receivedTx(msg, 'incoming', 'default')
        source.onerror = () => this._isUpdated = false
        source.onopen = () => this.checkForUpdate()
        if (Wallet.debug)
            console.log('created incoming source', source, query)
        return source
    }

    private listenToNonTokenOutgoing(): EventSource {
        const query = {
            "v": 3,
            "q": {
                "find": {
                    "in.e.a": this._addressBase,
                    "out.b1": {"$ne": SLP_B64},
                },
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const source = new EventSource("https://bitsocket.fountainhead.cash/s/" + queryBase64)
        source.onmessage = (msg) => this.receivedTx(msg, 'outgoing', 'default')
        source.onerror = () => this._isUpdated = false
        source.onopen = () => this.checkForUpdate()
        if (Wallet.debug)
            console.log('created outgoing source', source, query)
        return source
    }

    private listenToTokenIncoming(): EventSource {
        const query = {
            "v": 3,
            "q": {
                "find": {
                    "in": {"$not": {"$elemMatch": {"e.a": this.slpAddr()}}},
                    "out.e.a": this.slpAddr(),
                },
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const source = new EventSource("https://slpsocket.fountainhead.cash/s/" + queryBase64)
        source.onmessage = (msg) => this.receivedTx(msg, 'incoming', 'SLP')
        source.onerror = () => this._isUpdated = false
        source.onopen = () => this.checkForUpdate()
        if (Wallet.debug)
            console.log('created incoming source', source, query)
        return source
    }

    private listenToTokenOutgoing(): EventSource {
        const query = {
            "v": 3,
            "q": {
                "find": {
                    "in.e.a": this.slpAddr(),
                },
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const source = new EventSource("https://slpsocket.fountainhead.cash/s/" + queryBase64)
        source.onmessage = (msg) => this.receivedTx(msg, 'outgoing', 'SLP')
        source.onerror = () => this._isUpdated = false
        source.onopen = () => this.checkForUpdate()
        if (Wallet.debug)
            console.log('created outgoing source', source, query)
        return source
    }

    private receivedTx(msg: MessageEvent, direction: TxDirection, kind: TxKind) {
        const resp: {data: ReceivedTx[], type: string} = JSON.parse(msg.data)
        if (Wallet.debug)
            console.log(msg, resp, direction)
        if (resp.type == 'open' || resp.type == 'block')
            return
        this._isUpdated = false
        if (resp.type == 'mempool')
            this
                .updateWalletAndNotify(direction, async () => {
                    for (const tx of resp.data)
                        await this.applyReceivedTx(tx, direction, kind)
                })
                .then()
        setTimeout(() => this.updateWallet().then(), 7_000)
    }

    private checkForUpdate() {
        if (this._isUpdated || !this._isInitialized)
            return
        this._isWaitingToUpdate = true
        setTimeout(() => {
            if (!this._isWaitingToUpdate)
                return
            this._isWaitingToUpdate = false
            this.updateWallet().then()
        }, 500)
    }

    private async applyReceivedTxSLP(tx: ReceivedTx, direction: TxDirection): Promise<boolean> {
        const slp = tx.slp || keyError('slp')
        if (!slp.valid)
            return false
        for (const input of tx.in) {
            if (input.e.a == this.slpAddr()) {
                this._utxos.removeTokenUtxo(
                    slp.detail.tokenIdHex,
                    {
                        txid: input.e.h,
                        vout: input.e.i,
                    },
                )
            }
        }
        for (let vout = 0; vout < tx.out.length; ++vout) {
            const output = vout < slp.detail.outputs.length ? slp.detail.outputs[vout] : undefined
            const txOut = tx.out[vout]
            if (output !== undefined && output.address == this.slpAddr() && parseFloat(output.amount) != 0) {
                await this._utxos.addTokenUtxo({
                    tokenDetails: {
                        tokenIdHex: slp.detail.tokenIdHex,
                    },
                    txid: tx.tx.h,
                    vout,
                    bchSatoshis: txOut.e.v,
                    slpAmount: output.amount,
                })
            } else if (txOut.e.a == this.slpAddr()) {
                this._utxos.addNonTokenUtxo({
                    txid: tx.tx.h,
                    vout,
                    satoshis: new BigNumber(txOut.e.v),
                })
            }
        }
        return true
    }

    private async applyReceivedTxNonToken(tx: ReceivedTx) {
        for (const input of tx.in) {
            if (input.e.a == this._addressBase) {
                this._utxos.removeNonTokenUtxo({
                    txid: input.e.h,
                    vout: input.e.i,
                })
            }
        }
        for (const output of tx.out) {
            if (output.e.a == this._addressBase) {
                this._utxos.addNonTokenUtxo({
                    txid: tx.tx.h,
                    vout: output.e.i,
                    satoshis: new BigNumber(output.e.v),
                })
            }
        }
    }

    private async applyReceivedTx(tx: ReceivedTx, direction: TxDirection, kind: TxKind) {
        switch (kind) {
            case 'SLP':
                const accepted = await this.applyReceivedTxSLP(tx, direction)
                if (!accepted)
                    this.applyReceivedTxNonToken(tx)
                return
            case 'default':
                this.applyReceivedTxNonToken(tx)
                return
        }
    }

    public async updateWallet(): Promise<void> {
        await this.updateWalletAndNotify('update', () => this._utxos.update())
    }

    private async updateWalletAndNotify(direction: TxDirection, update: () => Promise<void>): Promise<void> {
        const balanceBefore = this.nonTokenBalance()
        const balanceTokensBefore = Map(this.tokenIds().map(tokenId => [tokenId, this.tokenBalance(tokenId)]))
        await update()
        this._isUpdated = true
        if (!this._isInitialized) {
            this._isInitialized = true
            return
        }
        this._isInitialized = true
        const event: TxEvent = {
            direction,
            nonTokenDelta: this.nonTokenBalance().minus(balanceBefore),
            tokenDelta: Map(
                Set(balanceTokensBefore.keySeq().concat(this._utxos.tokenIds()))
                    .map(tokenId => [tokenId, this.tokenBalance(tokenId).minus(balanceTokensBefore.get(tokenId, '0'))])
            ).filter(delta => !delta.isZero())
        }
        if (event.nonTokenDelta.isZero() && event.tokenDelta.size == 0)
            return
        if (Wallet.debug)
            console.log('event', event, event.tokenDelta.toJS())
        this._receivedTxListeners.forEach(listener => listener(event))
    }

    public static async create(secret: Uint8Array): Promise<Wallet> {
        try {
            await cashcontracts.ready
            const curve = await bitcoin.instantiateSecp256k1()
            const pubkey = curve.derivePublicKeyCompressed(secret)
            const address = cashcontracts.Address.from_pub_key_hex("bitcoincash", "P2PKH", bufferToHex(pubkey))
            const wallet = cashcontracts.Wallet.from_cash_addr(address.cash_addr())
            const slpAddress = address.with_prefix("simpleledger")
            const addressBase = address.cash_addr().substr(address.cash_addr().indexOf(':') + 1)
            const endpoint = new EndpointDefault()
            const tokenDetailStore = new TokenDetailStore(endpoint)
            const utxos = new Utxos(address.cash_addr(), slpAddress.cash_addr(), endpoint, tokenDetailStore)
            const result = new Wallet(curve, secret, pubkey, wallet, address, slpAddress, addressBase, utxos, tokenDetailStore)
            result._sha256 = await bitcoin.instantiateSha256()
            await result.updateWallet()
            return result
        } catch (e) {
            console.error(e)
            throw e
        }
    }

    public static async loadFromStorage(): Promise<Wallet> {
        const secretHex = localStorage.getItem("secret")
        if (secretHex === null) {
            throw "No secret in storage. Set or generate one with storeSecret or storeRandomSecret."
        }
        return await Wallet.create(hexToBuffer(secretHex))
    }

    public static isSecretInStorage(): boolean {
        return localStorage.getItem("secret") !== null
    }

    public static storeSecret(secret: Uint8Array, override: boolean = false) {
        if (Wallet.isSecretInStorage() && !override)
            throw "Secret already exists in storage"
        localStorage.setItem("secret", bufferToHex(secret))
    }

    public static storeRandomSecret(override: boolean = false) {
        if (Wallet.isSecretInStorage() && !override)
            throw "Secret already exists in storage"
        const secret = new Uint8Array(32)
        window.crypto.getRandomValues(secret)
        Wallet.storeSecret(secret, override)
    }

    public addReceivedTxListener(listener: (direction: TxEvent) => void) {
        if (Wallet.debug)
            console.log('addReceivedTxListener', listener)
        this._receivedTxListeners.push(listener)
    }

    public cashAddr(): string {
        return this._address.cash_addr()
    }

    public slpAddr(): string {
        return this._slpAddress.cash_addr()
    }

    public nonTokenBalance(): BigNumber {
        return this._utxos.nonTokenUtxos()
            .map((utxoEntry) => utxoEntry.satoshis)
            .reduce((a, b) => a.plus(b), new BigNumber('0'))
    }

    public tokenIds(): List<string> {
        return this._utxos.tokenIds()
    }

    public tokenBalance(tokenId: TokenId): BigNumber {
        const utxos = this._utxos.tokenUtxos().get(tokenId)
        if (utxos === undefined)
            return new BigNumber('0')
        return utxos
            .map(utxoEntry => parseFloat(utxoEntry.slpAmount))
            .reduce((a, b) => a.plus(b), new BigNumber('0'))
    }

    public tokenDetails(tokenId: TokenId): TokenDetails {
        return this._tokenDetailStore.tokenDetails().get(tokenId, keyError(tokenId))
    }

    public toTokenBaseAmount(tokenId: TokenId, amount: BigNumber): BigNumber {
        return amount.times(new BigNumber('10').pow(this._tokenDetailStore.tokenDetails().get(tokenId, keyError(tokenId)).decimals))
    }

    public initNonTokenTx(include: "none" | undefined = undefined): UnsignedTx {
        const nonTokenUtxos = include == "none" ? [] : this._utxos.nonTokenUtxos().map(utxo => ({
            tx_id_hex: utxo.txid,
            vout: utxo.vout,
            amount: utxo.satoshis.toFixed(0),
        })).valueSeq().toArray()
        return new UnsignedTx(
            this._curve,
            this._secret,
            this._pubkey,
            nonTokenUtxos.length,
            this._wallet.init_tx(nonTokenUtxos)
        )
    }

    public initTokenTx(tokenId: TokenId, include: "none" | "nonToken" | undefined = undefined): UnsignedTokenTx {
        const nonTokenUtxos = include === undefined || include == "nonToken" ? this._utxos.nonTokenUtxos() : Map<string, UtxoEntry>()
        const tokenUtxos = include === undefined ? this._utxos.tokenUtxos().get(tokenId, keyError(tokenId)) : Map<string, SLPUtxoEntry>()
        const tokenDetails = this._tokenDetailStore.tokenDetails().get(tokenId, keyError(tokenId))
        return new UnsignedTokenTx(
            this._curve,
            this._secret,
            this._pubkey,
            tokenDetails,
            tokenUtxos.map(utxo => utxo.slpBaseAmount).concat(nonTokenUtxos.map(() => new BigNumber('0'))).valueSeq().toArray(),
            this._wallet.init_tx(
                tokenUtxos
                    .map(utxo => ({
                        tx_id_hex: utxo.txid,
                        vout: utxo.vout,
                        amount: utxo.bchSatoshis.toFixed(0),
                    }))
                    .concat(nonTokenUtxos.map(utxo => ({
                        tx_id_hex: utxo.txid,
                        vout: utxo.vout,
                        amount: utxo.satoshis.toFixed(0),
                    })))
                    .valueSeq()
                    .toArray()
            ),
        )
    }

    public doubleSha256(msg: Uint8Array): Uint8Array {
        return this._sha256.hash(this._sha256.hash(msg))
    }

    public privateKey(): PrivateKey {
        return new PrivateKey(this._secret, this._sha256, undefined)
    }
}

interface UtxoEntryRemote {
    txid: string
    vout: number
    satoshis: number
}

export interface UtxoEntry {
    txid: string
    vout: number
    satoshis: BigNumber
}

interface SLPUtxoEntryRemote {
    tokenDetails: {
        tokenIdHex: string
    }
    txid: string
    vout: number
    bchSatoshis: number
    slpAmount: string
}

interface SLPUtxoEntry extends SLPUtxoEntryRemote {
    slpBaseAmount: BigNumber
    amountFactor: BigNumber
}

interface ReceivedTx {
    tx: {h: string}
    out: {
        i: number
        e: {
            v: number
            i: number
            a: string
        }
    }[]
    in: {
        i: number
        e: {
            h: string
            i: number
            a: string
        }
    }[]
    slp?: {
        detail: {
            tokenIdHex: string
            decimals: number
            outputs: {
                address: string
                amount: string
            }[]
        }
        valid: boolean
    }
}

export class PrivateKey {
    private _secret: Uint8Array
    private _wif: string

    public constructor(secret: Uint8Array, sha256: bitcoin.Sha256 | undefined, wif: string | undefined) {
        this._secret = secret
        if (wif !== undefined)
            this._wif = wif
        else if (sha256 !== undefined)
            this._wif = this._calcWif(sha256)
        else
            throw 'Must provide either sha256 or wif'
    }

    private _calcWif(sha256: bitcoin.Sha256): string {
        const extendedKey = [0x80].concat(Array.from(this._secret)).concat([0x01])
        const doubleSha256 = sha256.hash(sha256.hash(new Uint8Array(extendedKey)))
        extendedKey.push(...doubleSha256.slice(0, 4))
        return cashcontracts.base58encode(new Uint8Array(extendedKey))
    }

    public static fromWif(wif: string, sha256: bitcoin.Sha256 | undefined): PrivateKey {
        const bytes = cashcontracts.base58decode(wif)
        const extendedKey = bytes.slice(0, bytes.length - 4)
        const checksum = bytes.slice(bytes.length - 4)
        if (sha256 !== undefined) {
            const doubleSha256 = sha256.hash(sha256.hash(new Uint8Array(extendedKey)))
            const actualChecksum = doubleSha256.slice(0, 4)
            const isEqual = Array.from(checksum)
                .map((item, idx) => actualChecksum[idx] == item)
                .reduce((a,b) => a && b)
            if (!isEqual)
                throw "Invalid checksum"
        }
        const secret = extendedKey.slice(1, extendedKey.length - 1)
        return new PrivateKey(secret, undefined, wif)
    }

    public wif(): string {
        return this._wif
    }

    public secret(): Uint8Array {
        return this._secret
    }
}

export interface TokenDetails {
    id: string
    timestamp: string
    symbol: string
    name: string
    documentUri: string
    documentHash: string
    decimals: number,
    initialTokenQty: number
}

export interface P2PKH {
    type: 'P2PKH'
    address: string
    amount: string
}
export interface P2SH {
    type: 'P2SH'
    output: OutputType
}
export interface OpReturn {
    type: 'OpReturn'
    data: string[]
}
export interface SLP {
    type: 'SLP'
    token_type: number
    token_id_hex: string
    output_quantities: string[]
}
export interface AdvancedTradeOffer {
    type: 'AdvancedTradeOffer'
    amount: string
    lokad_id: string
    version: number
    power: number
    is_inverted: boolean
    token_id_hex: string
    token_type: number
    sell_amount_token: string
    price: string
    address: string
    spend_params: string | undefined
    fee_address: string,
    fee_divisor: number,
}
export interface P2PKHDropNOutput {
    type: 'P2PKHDropNOutput',
    amount: string,
    address: string,
    drop_number: number,
    push_data?: string[],
}
export interface PushOfferData {
    type: 'PushOfferData'
    amount: string
    receiving_address: string
    lokad_id: string
    version: number
    power: number
    is_inverted: boolean
    price: number
    push_address: string
}
export type OutputType = P2PKH | P2SH | OpReturn | SLP | AdvancedTradeOffer | P2PKHDropNOutput | PushOfferData

export interface UnsignedInput {
    tx_id_hex: string
    vout: number
    sequence: number
    output: OutputType
}

export class UnsignedTx {
    private curve: bitcoin.Secp256k1
    private secret: Uint8Array
    private pubkey: Uint8Array
    private unsignedTx: cashcontracts.UnsignedTx
    private inputSecrets: Uint8Array[]
    private inputPubkeys: Uint8Array[]

    constructor(curve: bitcoin.Secp256k1, secret: Uint8Array, pubkey: Uint8Array, numWalletInputs: number, unsignedTx: cashcontracts.UnsignedTx) {
        this.curve = curve
        this.secret = secret
        this.pubkey = pubkey
        this.unsignedTx = unsignedTx
        this.inputSecrets = new Array(numWalletInputs).fill(this.secret)
        this.inputPubkeys = new Array(numWalletInputs).fill(this.pubkey)
    }

    addInput(input: UnsignedInput): number {
        this.inputSecrets.push(this.secret)
        this.inputPubkeys.push(this.pubkey)
        return err(() => this.unsignedTx.add_input(input))
    }

    addInputWithSecret(input: UnsignedInput, secret: Uint8Array): number {
        this.inputSecrets.push(secret)
        this.inputPubkeys.push(this.curve.derivePublicKeyCompressed(secret))
        return err(() => this.unsignedTx.add_input(input))
    }

    addOutput(output: OutputType): number {
        return err(() => this.unsignedTx.add_output(output))
    }

    addLeftoverOutput(address: string, feePerKb?: number, ignoreOverspend?: boolean): number | undefined {
        return err(() => this.unsignedTx.add_leftover_output(address, feePerKb, ignoreOverspend))
    }

    insertLeftoverOutput(leftover_idx: number, address: string, feePerKb?: number) {
        err(() => this.unsignedTx.insert_leftover_output(leftover_idx, address, feePerKb, undefined))
    }

    sign(): Tx {
        const preImages: string[] = err(() => this.unsignedTx.pre_image_hashes())
        const signatures = err(() => preImages.map((hash, idx) => {
            return bufferToHex(this.curve.signMessageHashDER(this.inputSecrets[idx], hexToBuffer(hash)))
        }))
        return err(() => new Tx(this.unsignedTx.sign(signatures, this.inputPubkeys.map(bufferToHex))))
    }

    estimateSize(): number {
        return this.unsignedTx.estimate_size()
    }
}

export class UnsignedTokenTx {
    private curve: bitcoin.Secp256k1
    private secret: Uint8Array
    private pubkey: Uint8Array
    private unsignedTx: cashcontracts.UnsignedTx | undefined
    private tokenDetails: TokenDetails
    private tokenFactor: BigNumber
    private inputSecrets: Uint8Array[]
    private inputPubkeys: Uint8Array[]
    private tokenInputAmounts: BigNumber[] = []
    private tokenOutputAmounts: BigNumber[] = []
    private outputs: OutputType[] = []

    constructor(curve: bitcoin.Secp256k1,
                secret: Uint8Array,
                pubkey: Uint8Array,
                tokenDetails: TokenDetails,
                tokenInputAmounts: BigNumber[], 
                unsignedTx: cashcontracts.UnsignedTx) {
        this.curve = curve
        this.secret = secret
        this.pubkey = pubkey
        this.tokenDetails = tokenDetails
        this.tokenFactor = new BigNumber('10').pow(tokenDetails.decimals)
        this.unsignedTx = unsignedTx
        this.inputSecrets = tokenInputAmounts.map(() => secret)
        this.inputPubkeys = tokenInputAmounts.map(() => pubkey)
        this.tokenInputAmounts = tokenInputAmounts
    }

    addNonTokenInput(input: UnsignedInput, secret?: Uint8Array): number {
        return this.addTokenInput(input, new BigNumber('0'), secret)
    }

    addTokenInput(input: UnsignedInput, tokenAmount: BigNumber, secret?: Uint8Array): number {
        if (this.unsignedTx === undefined)
            throw "Transaction has already been signed"
        if (secret === undefined) {
            this.inputSecrets.push(this.secret)
            this.inputPubkeys.push(this.pubkey)
        } else {
            this.inputSecrets.push(secret)
            this.inputPubkeys.push(this.curve.derivePublicKeyCompressed(secret))
        }
        this.tokenInputAmounts.push(tokenAmount.times(this.tokenFactor))
        if (Wallet.debug)
            console.log('add input', input, tokenAmount)
        return this.unsignedTx.add_input(input)
    }

    addNonTokenOutput(output: OutputType) {
        this.addTokenOutput(output, new BigNumber('0'))
    }

    addTokenOutput(output: OutputType, tokenAmount: BigNumber) {
        if (this.unsignedTx === undefined)
            throw "Transaction has already been signed"
        this.tokenOutputAmounts.push(tokenAmount.times(this.tokenFactor))
        this.outputs.push(output)
    }

    private prepareTransaction(nonTokenAddress: string, tokenAddress: string, feePerKb?: number, ignoreOverspend?: boolean): cashcontracts.UnsignedTx {
        if (this.unsignedTx === undefined)
            throw "Transaction has already been signed"
        const tokenLeftover = this.tokenInputAmounts.reduce((a, b) => a.plus(b)).minus(this.tokenOutputAmounts.reduce((a, b) => a.plus(b)))
        if (tokenLeftover.gt(0))
            this.tokenOutputAmounts.push(tokenLeftover)
        this.unsignedTx.add_output({
            type: "SLP",
            token_id_hex: this.tokenDetails.id,
            token_type: 1,
            output_quantities: this.tokenOutputAmounts.map(v => v.toFixed(0))
        } as OutputType)
        if (Wallet.debug)
            console.log(this.outputs, this.unsignedTx)
        this.outputs.forEach(output => this.unsignedTx!.add_output(output))
        if (tokenLeftover.gt(0))
            this.unsignedTx.add_output({
                type: "P2PKH",
                address: tokenAddress,
                amount: DUST_AMOUNT.toFixed(0),
            } as OutputType)
        this.unsignedTx.add_leftover_output(nonTokenAddress, feePerKb, ignoreOverspend)
        return this.unsignedTx
    }

    sign(nonTokenAddress: string, tokenAddress: string, feePerKb?: number): Tx {
        const unsignedTx = this.prepareTransaction(nonTokenAddress, tokenAddress, feePerKb)
        const preImages: string[] = unsignedTx.pre_image_hashes()
        const signatures = preImages.map((hash, idx) => {
            return bufferToHex(this.curve.signMessageHashDER(this.inputSecrets[idx], hexToBuffer(hash)))
        })
        const tx = new Tx(unsignedTx.sign(signatures, this.inputPubkeys.map(bufferToHex)))
        this.unsignedTx = undefined
        return tx
    }

    estimateSize(feePerKb?: number): number {
        const unsignedTx = this.prepareTransaction(EMPTY_CASH_ADDR, EMPTY_SLP_ADDR, feePerKb, true)
        return unsignedTx.estimate_size()
    }
}

export type BroadcastResult = {success: true, txid: string} | {success: false, msg: string}

export class Tx {
    private tx: cashcontracts.Tx

    constructor(tx: cashcontracts.Tx) {
        this.tx = tx
    }

    hex(): string {
        return this.tx.hex()
    }

    async broadcast(): Promise<BroadcastResult> {
        const response = await fetch("https://rest.bitcoin.com/v2/rawtransactions/sendRawTransaction/" + this.hex())
        const result = await response.text()
        if (result.startsWith('{')) {
            const responseJson = JSON.parse(result)
            if (responseJson.error)
                return {success: false, msg: responseJson.error}
        }
        return {success: true, txid: result.replace(/"/g, '')}
    }
}

export interface TxHistoryEntry {
    txid: string
    tokenId: string | null
    timestamp: number | undefined
    isSlp: boolean
    inputs: {
        slpAmountHex: string | null
        satoshiAmount: number
        address: string
    }[]
    outputs: {
        slpAmountHex: string | null
        satoshiAmount: number
        address: string
        vout: number
    }[]
}

export interface TxHistoryItem {
    txid: string
    tokenId: string | undefined
    timestamp: number | undefined
    deltaSatoshis: BigNumber
    deltaBaseToken: BigNumber | undefined
    outputs: {
        slpAmount: BigNumber
        satoshiAmount: number
        vout: number
    }[]
}

export class AddressTxHistory {
    private _slpAddress: string
    private _cashAddress: string
    private _baseAddress: string
    private _txHistory: Map<TokenId, TxHistoryItem> = Map()
    private _receivedTxListeners: (() => void)[] = []

    private constructor(slpAddress: string, cashAddress: string) {
        this._slpAddress = slpAddress
        this._cashAddress = cashAddress
        this._baseAddress = this._cashAddress.substr('bitcoincash:'.length)
    }

    public static async create(slpAddress: string, cashAddress: string): Promise<AddressTxHistory> {
        const txHistory = new AddressTxHistory(slpAddress, cashAddress)
        await txHistory._fetchTokenHistory()
        txHistory._listenToTxs()
        return txHistory
    }

    private async _fetchTokenHistory() {
        const query = {
            "v": 3,
            "q": {
                "db": ["u", "c"],
                "aggregate": [
                    {
                        "$match": {
                            "$or": [
                                {"in.e.a": this._baseAddress},
                                {"out.e.a": this._baseAddress},
                            ],
                        },
                    },
                    {
                        "$unwind": "$in",
                    },
                    {
                        "$lookup": {
                            "from": "confirmed",
                            "localField": "in.e.h",
                            "foreignField": "tx.h",
                            "as": "prevConfirmedTx",
                        },
                    },
                    {
                        "$lookup": {
                            "from": "unconfirmed",
                            "localField": "in.e.h",
                            "foreignField": "tx.h",
                            "as": "prevUnconfirmedTx",
                        },
                    },
                    {
                        "$addFields": {
                            "prevTx": {
                                "$arrayElemAt": [
                                    {"$concatArrays": ["$prevConfirmedTx", "$prevUnconfirmedTx"]},
                                    0,
                                ],
                            },
                        },
                    },
                    {
                        "$addFields": {
                            "slpOutput": {"$arrayElemAt": ["$prevTx.out", 0]},
                            "satoshiOutput": {
                                "$arrayElemAt": [
                                    "$prevTx.out",
                                    "$in.e.i",
                                ],
                            },
                        },
                    },
                    {
                        "$group": {
                            "_id": "$tx.h",
                            "prevSlpInput": {"$push": "$slpOutput"},
                            "prevInputs": {"$push": "$satoshiOutput"},
                            "txInputs": {"$push": "$in"},
                            "outputs": {"$first": "$out"},
                            "timestamp": {"$first": "$blk.t"},
                        },
                    },
                    {
                        "$sort": {
                            "timestamp": 1,
                        },
                    },
                ],
            },
            "r": {
                "f": `[.[] | {
                    txid: ._id,
                    inputs: [
                        . as $tx |
                        .txInputs | length | range(.) |
                        {
                            slpAmountHex: $tx.prevSlpInput[.][("h" + (($tx.txInputs[.].e.i + 4) | tostring))],
                            satoshiAmount: $tx.prevInputs[.].e.v,
                            address: $tx.prevInputs[.].e.a,
                        }
                    ],
                    outputs: [
                        . as $tx |
                        .outputs | length | range(.) |
                        select($tx.outputs[.].b1 != "${SLP_B64}") |
                        {
                            slpAmountHex: $tx.outputs[0][("h" + ((. + 4) | tostring))],
                            satoshiAmount: $tx.outputs[.].e.v,
                            address: $tx.outputs[.].e.a,
                            vout: $tx.outputs[.].e.i,
                        }
                    ],
                    isSlp: (.outputs[0].b1 == "${SLP_B64}"),
                    tokenId: .outputs[0].h4,
                    timestamp: .timestamp,
                }]`.replace(/\r?\n|\r/g, ''),
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const response = await fetch("https://bitdb.fountainhead.cash/q/" + queryBase64)
        const utxosJson: {c: TxHistoryEntry[], u: TxHistoryEntry[]} = await response.json()
        const txHistoryEntries = utxosJson.c.concat(utxosJson.u)
        console.log(txHistoryEntries)
        this._txHistory = this._txHistory.merge(Map(txHistoryEntries
            .map(entry => ({
                ...entry,
                outputs: entry.outputs
                    .filter(output => output.address == this._baseAddress)
                    .map(output => ({
                        ...output,
                        slpAmount: output.slpAmountHex ? new BigNumber(output.slpAmountHex, 16) : new BigNumber('0'),
                    })),
                inputs: entry.inputs
                    .filter(input => input.address == this._baseAddress)
                    .map(input => ({
                        ...input,
                        slpAmount: input.slpAmountHex ? new BigNumber(input.slpAmountHex, 16) : new BigNumber('0'),
                    })),
            }))
            .map(entry => {
                return [
                    entry.txid,
                    {
                        txid: entry.txid,
                        tokenId: entry.isSlp && entry.tokenId ? entry.tokenId : undefined,
                        timestamp: entry.timestamp || undefined,
                        deltaSatoshis: new BigNumber(
                            entry.outputs
                                .map(output => output.slpAmount.isZero() ? output.satoshiAmount : 0)
                                .reduce((a, b) => a + b, 0)
                            - entry.inputs
                                .map(input => input.slpAmount.isZero() ? input.satoshiAmount : 0)
                                .reduce((a, b) => a + b, 0)
                        ),
                        deltaBaseToken: entry.isSlp ?
                            entry.outputs
                                .map(output => output.slpAmount)
                                .reduce((a, b) => a.plus(b), new BigNumber('0'))
                                .minus(
                                    entry.inputs
                                        .map(input => input.slpAmount)
                                        .reduce((a, b) => a.plus(b), new BigNumber('0'))
                                ) :
                            undefined,
                        outputs: entry.outputs.map(output => ({
                            slpAmount: output.slpAmount,
                            satoshiAmount: output.satoshiAmount,
                            vout: output.vout,
                        }))
                    }
                ]
            })
        ))
        console.log(this._txHistory.toJS())
    }

    private _listenToTxs(): EventSource {
        const query = {
            "v": 3,
            "q": {
                "find": {
                    "$or": [
                        {"in.e.a": this._baseAddress},
                        {"out.e.a": this._baseAddress},
                    ],
                },
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const source = new EventSource("https://bitsocket.fountainhead.cash/s/" + queryBase64)
        source.onmessage = (msg) => this._receivedTx(msg)
        if (Wallet.debug)
            console.log('created incoming source', source, query)
        return source
    }

    private _receivedTx(msg: MessageEvent) {
        const resp: {data: ReceivedTx[], type: string} = JSON.parse(msg.data)
        if (Wallet.debug)
            console.log(msg, resp)
        if (resp.type == 'open' || resp.type == 'block')
            return
        if (resp.type == 'mempool') {
            for (const tx of resp.data) {
                let spentSatoshis = 0
                let spentTokens = new BigNumber('0')
                let receivedSatoshis = 0
                let receivedTokens = new BigNumber('0')
                tx.in.forEach(input => {
                    const prevTx = this._txHistory.get(input.e.h)
                    if (prevTx !== undefined) {
                        const utxo = prevTx.outputs.find(output => output.vout == input.e.i)
                        if (utxo !== undefined) {
                            spentSatoshis += utxo.satoshiAmount
                            spentTokens = spentTokens.plus(utxo.slpAmount)
                        }
                    }
                }, 0)
                const slpOutput: {[k: string]: string | undefined} = tx.out[0] as any
                const outputs: TxHistoryItem["outputs"] = []
                let tokenId: string | undefined = undefined
                tx.out.forEach(output => {
                    if (output.e.a == this._baseAddress) {
                        let slpAmount = new BigNumber('0')
                        if (slpOutput && slpOutput["b1"] == SLP_B64) {
                            const slpAmountHex = slpOutput["h" + (output.e.i + 4)]
                            if (slpAmountHex !== undefined)
                                slpAmount = new BigNumber(slpAmountHex)
                        }
                        outputs.push({
                            slpAmount,
                            satoshiAmount: output.e.v,
                            vout: output.e.i,
                        })
                        tokenId = slpOutput["h4"]
                        receivedSatoshis += output.e.v
                        receivedTokens = receivedTokens.plus(slpAmount)
                    }
                })
                if (Wallet.debug)
                    console.log({
                        txid: tx.tx.h,
                        tokenId,
                        timestamp: undefined,
                        deltaSatoshis: new BigNumber(receivedSatoshis - spentSatoshis),
                        deltaBaseToken: receivedTokens.minus(spentTokens),
                        outputs,
                    })
                this._txHistory = this._txHistory.set(
                    tx.tx.h,
                    {
                        txid: tx.tx.h,
                        tokenId,
                        timestamp: undefined,
                        deltaSatoshis: new BigNumber(receivedSatoshis - spentSatoshis),
                        deltaBaseToken: receivedTokens.minus(spentTokens),
                        outputs,
                    }
                )
                if (Wallet.debug)
                    console.log(this._txHistory.toJS())
            }
            this._receivedTxListeners.forEach(listener => listener())
        }
    }

    public addReceivedTxListener(listener: () => void) {
        if (Wallet.debug)
            console.log('addReceivedTxListener', listener)
        this._receivedTxListeners.push(listener)
    }

    public txHistory(): Map<TokenId, TxHistoryItem> {
        return this._txHistory
    }
}

export function sendToAddressTx(wallet: Wallet, address: string, amount: BigNumber): Tx {
    const txBuild = wallet.initNonTokenTx()
    txBuild.addOutput({
        type: 'P2PKH',
        address: address,
        amount: amount.toFixed(0),
    })
    txBuild.addLeftoverOutput(wallet.cashAddr())
    return txBuild.sign()
}

export function sendTokensToAddressTx(wallet: Wallet, address: string, tokenId: TokenId, amount: BigNumber): Tx {
    const txBuild = wallet.initTokenTx(tokenId)
    txBuild.addTokenOutput(
        {
            type: 'P2PKH',
            address: address,
            amount: DUST_AMOUNT.toFixed(0),
        },
        amount,
    )
    return txBuild.sign(wallet.cashAddr(), wallet.slpAddr())
}

export function feeSendNonToken(wallet: Wallet, amount: BigNumber): BigNumber {
    const txBuild = wallet.initNonTokenTx()
    txBuild.addOutput({
        type: 'P2PKH',
        address: EMPTY_CASH_ADDR,
        amount: amount.toFixed(0),
    })
    txBuild.addLeftoverOutput(wallet.cashAddr(), undefined, true)
    return new BigNumber(txBuild.estimateSize())
}

export function feeSendToken(wallet: Wallet, tokenId: string, amount: BigNumber): BigNumber {
    const txBuild = wallet.initTokenTx(tokenId)
    txBuild.addTokenOutput(
        {
            type: 'P2PKH',
            address: EMPTY_SLP_ADDR,
            amount: DUST_AMOUNT.toFixed(0),
        },
        amount,
    )
    return new BigNumber(txBuild.estimateSize())
}

export interface TradeOfferParams {
    tokenId: TokenId
    sellAmountToken: BigNumber
    pricePerToken: BigNumber
    receivingAddress: string
    feeAddress: string
    feeDivisor: BigNumber
    buyAmountToken?: BigNumber
}

interface TransformedOfferParams {
    tokenFactor: BigNumber
    pricePerBaseToken: BigNumber
    isInverted: boolean
    scriptPrice: BigNumber
    sellAmountBaseToken: BigNumber
    scriptBuyAmount: string | undefined
}

function transformOfferParams(tokenFactor: BigNumber, params: TradeOfferParams, adjustPrice=false): TransformedOfferParams {
    let pricePerBaseToken = params.pricePerToken.div(tokenFactor)
    let isInverted = pricePerBaseToken.lt('1')
    let scriptPrice = isInverted ? new BigNumber('1').div(pricePerBaseToken) : pricePerBaseToken
    if (!scriptPrice.isInteger()) {
        if (adjustPrice) {
            scriptPrice = scriptPrice.integerValue(BigNumber.ROUND_HALF_DOWN)
            pricePerBaseToken = isInverted ? new BigNumber('1').div(scriptPrice) : scriptPrice
            isInverted = pricePerBaseToken.lt('1')
        }
        else {
            throw "pricePerToken must either be an integer or the inverse of an integer."
        }
    }
    const sellAmountBaseToken = params.sellAmountToken.times(tokenFactor)
    const toScriptBuyAmount = (buyAmountToken: BigNumber) => {
        const buyAmountBaseToken = buyAmountToken.times(tokenFactor)
        if (isInverted) return buyAmountBaseToken
        return buyAmountBaseToken.times(pricePerBaseToken)
    }
    const scriptBuyAmount = params.buyAmountToken !== undefined ?
        toScriptBuyAmount(params.buyAmountToken).toFixed(0) :
        undefined
    return {tokenFactor, pricePerBaseToken, isInverted, scriptPrice, sellAmountBaseToken, scriptBuyAmount}
}

function tradeOfferOutput(tokenFactor: BigNumber, params: TradeOfferParams): AdvancedTradeOffer {
    const transformed = transformOfferParams(tokenFactor, params, true)
    return {
        type: 'AdvancedTradeOffer',
        amount: DUST_AMOUNT.toFixed(0),
        lokad_id: "EXCH",
        version: 2,
        power: 0,
        is_inverted: transformed.isInverted,
        token_id_hex: params.tokenId,
        token_type: 1,
        sell_amount_token: transformed.sellAmountBaseToken.toFixed(0),
        price: transformed.scriptPrice.toFixed(0),
        address: params.receivingAddress,
        spend_params: transformed.scriptBuyAmount,
        fee_address: params.feeAddress,
        fee_divisor: params.feeDivisor.toNumber(),
    }
}

export function acceptTradeOfferTx(wallet: Wallet, utxo: UtxoEntry, params: TradeOfferParams, tokenDetails: {decimals: number}): Tx {
    const buyAmountToken = params.buyAmountToken
    if (buyAmountToken === undefined)
        throw "Must set buyAmountToken to a number"
    const tokenFactor = new BigNumber('10').pow(tokenDetails.decimals)
    const transformedParams = transformOfferParams(tokenFactor, params, true)
    const buyAmountBaseToken = buyAmountToken.times(transformedParams.tokenFactor)
    const remainingAmountBaseToken = transformedParams.sellAmountBaseToken.minus(buyAmountBaseToken)
    if (Wallet.debug)
        console.log('transformedParams', transformedParams)
    if (Wallet.debug)
        console.log('remainingAmountToken', remainingAmountBaseToken)
    const txBuild = wallet.initNonTokenTx()
    const offerInput = tradeOfferOutput(tokenFactor, params)
    const payAmount = transformedParams.pricePerBaseToken.times(buyAmountBaseToken)
    if (Wallet.debug) {
        console.log('offerInput', offerInput)
        console.log('slpAddress', wallet.slpAddr())
        console.log('payAmount', payAmount)
    }
    txBuild.addInputWithSecret(
        {
            tx_id_hex: utxo.txid,
            vout: utxo.vout,
            sequence: 0xffff_ffff,
            output: {
                type: 'P2SH',
                output: offerInput,
            }
        },
        new Uint8Array(new Array(32).fill(42)),
    )
    let numOutputs = 0
    txBuild.addOutput({
        type: 'SLP',
        token_id_hex: params.tokenId,
        token_type: 1,
        output_quantities: remainingAmountBaseToken.gt('0') ?
            [remainingAmountBaseToken.toFixed(0), "0", buyAmountBaseToken.toFixed(0)] :
            ["0", buyAmountBaseToken.toFixed(0)],
    }); numOutputs++;
    if (remainingAmountBaseToken.gt('0')) {
        txBuild.addOutput(
            {
                type: 'P2SH',
                output: tradeOfferOutput(tokenFactor, {
                    ...params,
                    sellAmountToken: remainingAmountBaseToken.div(tokenFactor),
                    buyAmountToken: undefined,
                })
            },
        ); numOutputs++;
    }
    txBuild.addOutput(
        {
            type: 'P2PKH',
            address: params.receivingAddress,
            amount: payAmount.toFixed(0),
        },
    ); numOutputs++;
    txBuild.addOutput(
        {
            type: 'P2PKH',
            address: wallet.slpAddr(),
            amount: DUST_AMOUNT.toFixed(0),
        },
    ); numOutputs++;
    txBuild.addOutput(
        {
            type: 'P2PKH',
            address: params.feeAddress,
            amount: BigNumber.max(payAmount.div(params.feeDivisor).integerValue(BigNumber.ROUND_DOWN), DUST_AMOUNT).toFixed(0),
        },
    ); numOutputs++;
    txBuild.insertLeftoverOutput(numOutputs - 1, wallet.cashAddr())
    const tx = txBuild.sign()
    if (Wallet.debug)
        console.log(tx.hex())
    return tx
}

export function advancedTradeOfferAddress(tokenFactor: BigNumber, params: TradeOfferParams): string {
    const output = tradeOfferOutput(tokenFactor, params)
    if (Wallet.debug)
        console.log(output)
    return cashcontracts.Address.from_output("simpleledger", output).cash_addr()
}

export function verifyAdvancedTradeOffer(wallet: Wallet, tokenFactor: BigNumber, params: TradeOfferParams) {
    if (!params.sellAmountToken.isFinite())
        return {success: false, msg: "token sell amount must be a finite number"}
    if (!params.pricePerToken.isFinite())
        return {success: false, msg: "price must be a finite number"}
    if (params.sellAmountToken.lte('0'))
        return {success: false, msg: "token sell amount must be greater than 0"}
    if (params.pricePerToken.lte('0'))
        return {success: false, msg: "price must be greater than 0"}
    if (params.buyAmountToken === undefined && wallet.tokenBalance(params.tokenId) < params.sellAmountToken)
        return {success: false, msg: "insufficient token funds"}
    let transformedParams
    try {
        transformedParams = transformOfferParams(tokenFactor, params, true)
    } catch (e) {
        return {success: false, msg: e}
    }
    if (transformedParams.pricePerBaseToken.gte(MAX_INT) || transformedParams.scriptPrice.gte(MAX_INT)) {
        return {success: false, msg: "price too large"}
    }
    if (transformedParams.sellAmountBaseToken.gte(MAX_INT)) {
        return {success: false, msg: "token sell amount too large"}
    }
    if (!transformedParams.sellAmountBaseToken.isInteger()) {
        return {success: false, msg: "token sell amount has too many decimals" + transformedParams.sellAmountBaseToken}
    }
    const maxBuyAmountSats = transformedParams.pricePerBaseToken.times(transformedParams.sellAmountBaseToken)
    if (maxBuyAmountSats.lt(DUST_AMOUNT)) {
        return {success: false, msg: "total cost is below dust limit (<0.000 005 46 BCH)"}
    }
    if (!maxBuyAmountSats.isInteger()) {
        return {success: false, msg: "total cost has too many decimals"}
    }
    if (maxBuyAmountSats.gt(MAX_INT)) {
        return {success: false, msg: "total cost too large"}
    }
    if (params.buyAmountToken !== undefined && transformedParams.scriptBuyAmount !== undefined) {
        const buyAmountBaseToken = params.buyAmountToken.times(tokenFactor)
        if (!buyAmountBaseToken.isFinite()) {
            return {success: false, msg: "token buy amount must a finite number"}
        }
        if (buyAmountBaseToken.lte('0')) {
            return {success: false, msg: "token buy amount must be greater than 0"}
        }
        const buyAmountSats = buyAmountBaseToken.times(transformedParams.pricePerBaseToken)
        if (buyAmountSats.lt(DUST_AMOUNT)) {
            return {success: false, msg: "cost is below dust limit (<0.000 005 46 BCH)"}
        }
        if (wallet.nonTokenBalance() < buyAmountSats)
            return {success: false, msg: "insufficient funds"}
        const remainingBuyAmountBase = maxBuyAmountSats.minus(buyAmountSats)
        if (remainingBuyAmountBase.gt('0') && remainingBuyAmountBase.lt(DUST_AMOUNT)) {
            return {success: false, msg: "remaining cost is below dust limit (<0.000 005 46 BCH)"}
        }
        if (new BigNumber(transformedParams.scriptBuyAmount).gte(MAX_INT)) {
            return {success: false, msg: "buy amount too large"}
        }
    }
    return {success: true}
}

export function createAdvancedTradeOfferTxs(wallet: Wallet, tokenFactor: BigNumber, params: TradeOfferParams) {
    if (params.buyAmountToken !== undefined)
        throw "params.buyAmountToken must be set to undefined"
    const offerTxMeasure = wallet.initTokenTx(params.tokenId, "none")
    const transformedParams = transformOfferParams(tokenFactor, params, true)
    const offerOutput: P2SH = {
        type: 'P2SH',
        output: tradeOfferOutput(tokenFactor, params),
    }
    const pushDataOutput: PushOfferData = {
        type: "PushOfferData",
        amount: (0xffff_ffff).toString(),
        receiving_address: wallet.slpAddr(),
        lokad_id: "EXCH",
        version: 2,
        power: 0,
        is_inverted: transformedParams.isInverted,
        price: transformedParams.scriptPrice.toNumber(),
        push_address: wallet.slpAddr(),
    }
    offerTxMeasure.addTokenInput(
        {
            tx_id_hex: '0000000000000000000000000000000000000000000000000000000000000000',
            vout: 0,
            sequence: 0xffff_ffff,
            output: {
                type: "P2SH",
                output: pushDataOutput,
            },
        },
        params.sellAmountToken,
    )
    offerTxMeasure.addTokenOutput(
        offerOutput,
        params.sellAmountToken,
    )
    const txSize = new BigNumber(offerTxMeasure.estimateSize())
    const neededAmount = txSize.plus(DUST_AMOUNT).plus('2')
    const glueTxBuild = wallet.initTokenTx(params.tokenId)
    const newPushDataOutput: P2SH = {
        type: "P2SH",
        output: {
            ...pushDataOutput,
            amount: neededAmount.toFixed(0),
        },
    }
    glueTxBuild.addTokenOutput(
        newPushDataOutput,
        params.sellAmountToken,
    )
    const glueTx = glueTxBuild.sign(wallet.cashAddr(), wallet.slpAddr())
    const glueTxHash = bufferToHex(wallet.doubleSha256(hexToBuffer(glueTx.hex())).reverse())
    
    const offerTx = wallet.initTokenTx(params.tokenId, "none")
    offerTx.addTokenInput(
        {
            tx_id_hex: glueTxHash,
            vout: 1,
            sequence: 0xffff_ffff,
            output: newPushDataOutput,
        },
        params.sellAmountToken,
    )
    offerTx.addTokenOutput(
        offerOutput,
        params.sellAmountToken,
    )
    return [glueTx, offerTx.sign(wallet.cashAddr(), wallet.slpAddr())]
}

export function cancelTradeOfferTx(wallet: Wallet, utxo: UtxoEntry, params: TradeOfferParams, tokenDetails: {decimals: number}): Tx {
    if (params.buyAmountToken !== undefined)
        throw "Must set buyAmountToken to undefined"
    const tokenFactor = new BigNumber(10).pow(tokenDetails.decimals)
    const transformedParams = transformOfferParams(tokenFactor, params, true)
    const txBuild = wallet.initNonTokenTx()
    const offerInput = tradeOfferOutput(tokenFactor, params)
    offerInput.spend_params = 'cancel'
    if (Wallet.debug) {
        console.log('offerInput', offerInput)
        console.log('slpAddress', wallet.slpAddr())
        console.log('utxo', utxo)
        console.log('params', params)
        console.log('transformedParams', transformedParams)
    }
    txBuild.addInput(
        {
            tx_id_hex: utxo.txid,
            vout: utxo.vout,
            sequence: 0xffff_ffff,
            output: {
                type: 'P2SH',
                output: offerInput,
            }
        },
    )
    txBuild.addOutput({
        type: 'SLP',
        token_id_hex: params.tokenId,
        token_type: 1,
        output_quantities: [transformedParams.sellAmountBaseToken.toFixed(0)],
    })
    txBuild.addOutput(
        {
            type: 'P2PKH',
            address: wallet.slpAddr(),
            amount: DUST_AMOUNT.toFixed(0),
        },
    )
    txBuild.addLeftoverOutput(wallet.cashAddr())
    const tx = txBuild.sign()
    if (Wallet.debug)
        console.log(tx.hex())
    return tx
}
