import * as bitcoin from "bitcoin-ts-cashcontracts"
import * as cashcontracts from "cashcontracts-wasm"
import { List, Map, Set } from "immutable"
import * as Immutable from "immutable"
import { Base64 } from 'js-base64'

export type TokenId = string
export type UtxoId = string

export const DUST_AMOUNT = 0x222


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

function sleep(milliseconds: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, milliseconds))
}

export type TxDirection = 'incoming' | 'outgoing' | 'update'
export type TxKind = 'SLP' | 'default'
export interface TxEvent {
    direction: TxDirection
    nonTokenDelta: number
    tokenDelta: Map<TokenId, number>
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
        const utxosJson: {utxos: UtxoEntry[]} = await (await fetch("https://rest.bitcoin.com/v2/address/utxo/" + address)).json()
        return List(utxosJson.utxos)
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
            const amountFactor = Math.pow(
                10,
                details.get(
                    utxo.tokenDetails.tokenIdHex,
                    keyError(utxo.tokenDetails.tokenIdHex)
                ).decimals,
            )
            return {
                ...utxo,
                slpBaseAmount: parseFloat(utxo.slpAmount) * amountFactor,
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
                    satoshis: txOut.e.v,
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
                    satoshis: output.e.v,
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
            nonTokenDelta: this.nonTokenBalance() - balanceBefore,
            tokenDelta: Map(
                Set(balanceTokensBefore.keySeq().concat(this._utxos.tokenIds()))
                    .map(tokenId => [tokenId, this.tokenBalance(tokenId) - balanceTokensBefore.get(tokenId, 0)])
            ).filter(delta => delta != 0)
        }
        if (event.nonTokenDelta == 0 && event.tokenDelta.size == 0)
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

    public totalBalance(): number {
        throw "Disabled totalBalance as the value requires burning all tokens"
    }

    public nonTokenBalance(): number {
        return this._utxos.nonTokenUtxos()
            .map((utxoEntry) => utxoEntry.satoshis)
            .reduce((a, b) => a + b, 0)
    }

    public tokenIds(): List<string> {
        return this._utxos.tokenIds()
    }

    public tokenBalance(tokenId: TokenId): number {
        const utxos = this._utxos.tokenUtxos().get(tokenId)
        if (utxos === undefined)
            return 0
        return utxos
            .map(utxoEntry => parseFloat(utxoEntry.slpAmount))
            .reduce((a, b) => a + b, 0)
    }

    public tokenDetails(tokenId: TokenId): TokenDetails {
        return this._tokenDetailStore.tokenDetails().get(tokenId, keyError(tokenId))
    }

    public toTokenBaseAmount(tokenId: TokenId, amount: number): number {
        return amount * Math.pow(10, this._tokenDetailStore.tokenDetails().get(tokenId, keyError(tokenId)).decimals)
    }

    public initNonTokenTx(include: "none" | undefined = undefined): UnsignedTx {
        const nonTokenUtxos = include == "none" ? [] : this._utxos.nonTokenUtxos().map(utxo => ({
            tx_id_hex: utxo.txid,
            vout: utxo.vout,
            amount: utxo.satoshis.toString(),
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
            tokenUtxos.map(utxo => utxo.slpBaseAmount).concat(nonTokenUtxos.map(() => 0)).valueSeq().toArray(),
            this._wallet.init_tx(
                tokenUtxos
                    .map(utxo => ({
                        tx_id_hex: utxo.txid,
                        vout: utxo.vout,
                        amount: utxo.bchSatoshis.toString(),
                    }))
                    .concat(nonTokenUtxos.map(utxo => ({
                        tx_id_hex: utxo.txid,
                        vout: utxo.vout,
                        amount: utxo.satoshis.toString(),
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
        return new PrivateKey(this._secret, this._sha256)
    }
}

interface UtxoEntry {
    txid: string
    vout: number
    satoshis: number
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
    slpBaseAmount: number
    amountFactor: number
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
    private secret: Uint8Array
    private sha256: bitcoin.Sha256

    public constructor(secret: Uint8Array, sha256: bitcoin.Sha256) {
        this.secret = secret
        this.sha256 = sha256
    }

    public wif(): string {
        const extendedKey = [0x80].concat(Array.from(this.secret)).concat([0x01])
        const doubleSha256 = this.sha256.hash(this.sha256.hash(new Uint8Array(extendedKey)))
        extendedKey.push(...doubleSha256.slice(0, 4))
        return cashcontracts.base58encode(new Uint8Array(extendedKey))
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
        this.inputSecrets.push(this.pubkey)
        return this.unsignedTx.add_input(input)
    }

    addInputWithSecret(input: UnsignedInput, secret: Uint8Array): number {
        this.inputSecrets.push(secret)
        this.inputPubkeys.push(this.curve.derivePublicKeyCompressed(secret))
        return this.unsignedTx.add_input(input)
    }

    addOutput(output: OutputType): number {
        return this.unsignedTx.add_output(output)
    }

    addLeftoverOutput(address: string, feePerKb?: number, ignoreOverspend?: boolean): number | undefined {
        return this.unsignedTx.add_leftover_output(address, feePerKb, ignoreOverspend)
    }

    insertLeftoverOutput(leftover_idx: number, address: string, feePerKb?: number) {
        this.unsignedTx.insert_leftover_output(leftover_idx, address, feePerKb, undefined)
    }

    sign(): Tx {
        const preImages: string[] = this.unsignedTx.pre_image_hashes()
        const signatures = preImages.map((hash, idx) => {
            return bufferToHex(this.curve.signMessageHashDER(this.inputSecrets[idx], hexToBuffer(hash)))
        })
        return new Tx(this.unsignedTx.sign(signatures, this.inputPubkeys.map(bufferToHex)))
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
    private tokenFactor: number
    private inputSecrets: Uint8Array[]
    private inputPubkeys: Uint8Array[]
    private tokenInputAmounts: number[] = []
    private tokenOutputAmounts: number[] = []
    private outputs: OutputType[] = []

    constructor(curve: bitcoin.Secp256k1,
                secret: Uint8Array,
                pubkey: Uint8Array,
                tokenDetails: TokenDetails,
                tokenInputAmounts: number[], 
                unsignedTx: cashcontracts.UnsignedTx) {
        this.curve = curve
        this.secret = secret
        this.pubkey = pubkey
        this.tokenDetails = tokenDetails
        this.tokenFactor = Math.pow(10, tokenDetails.decimals)
        this.unsignedTx = unsignedTx
        this.inputSecrets = tokenInputAmounts.map(() => secret)
        this.inputPubkeys = tokenInputAmounts.map(() => pubkey)
        this.tokenInputAmounts = tokenInputAmounts
    }

    addNonTokenInput(input: UnsignedInput, secret?: Uint8Array): number {
        return this.addTokenInput(input, 0, secret)
    }

    addTokenInput(input: UnsignedInput, tokenAmount: number, secret?: Uint8Array): number {
        if (this.unsignedTx === undefined)
            throw "Transaction has already been signed"
        if (secret === undefined) {
            this.inputSecrets.push(this.secret)
            this.inputPubkeys.push(this.pubkey)
        } else {
            this.inputSecrets.push(secret)
            this.inputPubkeys.push(this.curve.derivePublicKeyCompressed(secret))
        }
        this.tokenInputAmounts.push(tokenAmount * this.tokenFactor)
        if (Wallet.debug)
            console.log('add input', input, tokenAmount)
        return this.unsignedTx.add_input(input)
    }

    addNonTokenOutput(output: OutputType) {
        this.addTokenOutput(output, 0)
    }

    addTokenOutput(output: OutputType, tokenAmount: number) {
        if (this.unsignedTx === undefined)
            throw "Transaction has already been signed"
        this.tokenOutputAmounts.push(tokenAmount * this.tokenFactor)
        this.outputs.push(output)
    }

    private prepareTransaction(nonTokenAddress: string, tokenAddress: string, feePerKb?: number, ignoreOverspend?: boolean): cashcontracts.UnsignedTx {
        if (this.unsignedTx === undefined)
            throw "Transaction has already been signed"
        const tokenLeftover = this.tokenInputAmounts.reduce((a, b) => a + b) - this.tokenOutputAmounts.reduce((a, b) => a + b)
        if (tokenLeftover > 0)
            this.tokenOutputAmounts.push(tokenLeftover)
        this.unsignedTx.add_output({
            type: "SLP",
            token_id_hex: this.tokenDetails.id,
            token_type: 1,
            output_quantities: this.tokenOutputAmounts.map(v => v.toString())
        } as OutputType)
        if (Wallet.debug)
            console.log(this.outputs, this.unsignedTx)
        this.outputs.forEach(output => this.unsignedTx!.add_output(output))
        if (tokenLeftover > 0)
            this.unsignedTx.add_output({
                type: "P2PKH",
                address: tokenAddress,
                amount: DUST_AMOUNT.toString(),
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

export class Tx {
    private tx: cashcontracts.Tx

    constructor(tx: cashcontracts.Tx) {
        this.tx = tx
    }

    hex(): string {
        return this.tx.hex()
    }

    async broadcast(): Promise<string> {
        const response = await fetch("https://rest.bitcoin.com/v2/rawtransactions/sendRawTransaction/" + this.hex())
        return await response.text()
    }
}

export function sendToAddressTx(wallet: Wallet, address: string, amount: number): Tx {
    const txBuild = wallet.initNonTokenTx()
    txBuild.addOutput({
        type: 'P2PKH',
        address: address,
        amount: amount.toString(),
    })
    txBuild.addLeftoverOutput(wallet.cashAddr())
    return txBuild.sign()
}

export function sendTokensToAddressTx(wallet: Wallet, address: string, tokenId: TokenId, amount: number): Tx {
    const txBuild = wallet.initTokenTx(tokenId)
    txBuild.addTokenOutput(
        {
            type: 'P2PKH',
            address: address,
            amount: DUST_AMOUNT.toString(),
        },
        amount,
    )
    return txBuild.sign(wallet.cashAddr(), wallet.slpAddr())
}

export function feeSendNonToken(wallet: Wallet, amount: number): number {
    const txBuild = wallet.initNonTokenTx()
    txBuild.addOutput({
        type: 'P2PKH',
        address: EMPTY_CASH_ADDR,
        amount: amount.toString(),
    })
    txBuild.addLeftoverOutput(wallet.cashAddr(), undefined, true)
    return txBuild.estimateSize()
}

export function feeSendToken(wallet: Wallet, tokenId: string, amount: number): number {
    const txBuild = wallet.initTokenTx(tokenId)
    txBuild.addTokenOutput(
        {
            type: 'P2PKH',
            address: EMPTY_SLP_ADDR,
            amount: DUST_AMOUNT.toString(),
        },
        amount,
    )
    return txBuild.estimateSize()
}

export interface TradeOfferParams {
    tokenId: TokenId
    sellAmountToken: number
    pricePerToken: number
    receivingAddress: string
    feeAddress: string
    feeDivisor: number
    buyAmountToken?: number
}

interface TransformedOfferParams {
    tokenFactor: number;
    pricePerBaseToken: number;
    isInverted: boolean;
    scriptPrice: number;
    sellAmountBaseToken: number;
    scriptBuyAmount: string | undefined;
}

function transformOfferParams(wallet: Wallet, params: TradeOfferParams): TransformedOfferParams {
    const tokenFactor = wallet.toTokenBaseAmount(params.tokenId, 1)
    const pricePerBaseToken = params.pricePerToken / tokenFactor
    const isInverted = pricePerBaseToken < 1
    const scriptPrice = isInverted ? 1.0 / pricePerBaseToken : pricePerBaseToken
    if (!Number.isInteger(scriptPrice))
        throw "pricePerToken must either be an integer or the inverse of an integer."
    const sellAmountBaseToken = params.sellAmountToken * tokenFactor
    const toScriptBuyAmount = (buyAmountToken: number) => {
        const buyAmountBaseToken = buyAmountToken * tokenFactor
        if (isInverted) return buyAmountBaseToken
        return buyAmountBaseToken * pricePerBaseToken
    }
    const scriptBuyAmount = params.buyAmountToken !== undefined ?
        toScriptBuyAmount(params.buyAmountToken).toString() :
        undefined
    return {tokenFactor, pricePerBaseToken, isInverted, scriptPrice, sellAmountBaseToken, scriptBuyAmount}
}

function tradeOfferOutput(wallet: Wallet, params: TradeOfferParams): AdvancedTradeOffer {
    const transformed = transformOfferParams(wallet, params)
    return {
        type: 'AdvancedTradeOffer',
        amount: DUST_AMOUNT.toString(),
        lokad_id: "EXCH",
        version: 2,
        power: 0,
        is_inverted: transformed.isInverted,
        token_id_hex: params.tokenId,
        token_type: 1,
        sell_amount_token: transformed.sellAmountBaseToken.toString(),
        price: transformed.scriptPrice.toString(),
        address: params.receivingAddress,
        spend_params: transformed.scriptBuyAmount,
        fee_address: params.feeAddress,
        fee_divisor: params.feeDivisor,
    }
}

export function acceptTradeOfferTx(wallet: Wallet, utxo: UtxoEntry, params: TradeOfferParams): Tx {
    const buyAmountToken = params.buyAmountToken
    if (buyAmountToken === undefined)
        throw "Must set buyAmountToken to a number"
    const transformedParams = transformOfferParams(wallet, params)
    const buyAmountBaseToken = buyAmountToken * transformedParams.tokenFactor
    const remainingAmountBaseToken = transformedParams.sellAmountBaseToken - buyAmountBaseToken
    if (Wallet.debug)
        console.log('remainingAmountToken', remainingAmountBaseToken)
    const txBuild = wallet.initNonTokenTx()
    const offerInput = tradeOfferOutput(wallet, params)
    const payAmount = params.pricePerToken * buyAmountToken
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
        output_quantities: remainingAmountBaseToken > 0 ?
            [remainingAmountBaseToken.toString(), "0", buyAmountBaseToken.toString()] :
            ["0", buyAmountBaseToken.toString()],
    }); numOutputs++;
    if (remainingAmountBaseToken > 0) {
        txBuild.addOutput(
            {
                type: 'P2SH',
                output: tradeOfferOutput(wallet, {
                    ...params,
                    sellAmountToken: remainingAmountBaseToken,
                    buyAmountToken: undefined,
                })
            },
        ); numOutputs++;
    }
    txBuild.addOutput(
        {
            type: 'P2PKH',
            address: params.receivingAddress,
            amount: payAmount.toString(),
        },
    ); numOutputs++;
    txBuild.addOutput(
        {
            type: 'P2PKH',
            address: wallet.slpAddr(),
            amount: DUST_AMOUNT.toString(),
        },
    ); numOutputs++;
    txBuild.addOutput(
        {
            type: 'P2PKH',
            address: params.feeAddress,
            amount: Math.max(Math.floor(payAmount / params.feeDivisor), DUST_AMOUNT).toString(),
        },
    ); numOutputs++;
    txBuild.insertLeftoverOutput(numOutputs - 1, wallet.cashAddr())
    return txBuild.sign()
}

export function advancedTradeOfferAddress(wallet: Wallet, params: TradeOfferParams): string {
    const output = tradeOfferOutput(wallet, params)
    if (Wallet.debug)
        console.log(output)
    return cashcontracts.Address.from_output("simpleledger", output).cash_addr()
}

export function createAdvancedTradeOfferTxs(wallet: Wallet, params: TradeOfferParams) {
    if (params.buyAmountToken !== undefined)
        throw "params.buyAmountToken must be set to undefined"
    
    const offerTxMeasure = wallet.initTokenTx(params.tokenId, "none")
    const transformedParams = transformOfferParams(wallet, params)
    const offerOutput: P2SH = {
        type: 'P2SH',
        output: tradeOfferOutput(wallet, params),
    }
    const pushDataOutput: PushOfferData = {
        type: "PushOfferData",
        amount: (0xffff_ffff).toString(),
        receiving_address: wallet.slpAddr(),
        lokad_id: "EXCH",
        version: 2,
        power: 0,
        is_inverted: transformedParams.isInverted,
        price: transformedParams.scriptPrice,
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
    const txSize = offerTxMeasure.estimateSize()
    const neededAmount = txSize + DUST_AMOUNT + 2
    const glueTxBuild = wallet.initTokenTx(params.tokenId)
    const newPushDataOutput: P2SH = {
        type: "P2SH",
        output: {
            ...pushDataOutput,
            amount: neededAmount.toString(),
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
