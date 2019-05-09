import * as bitcoin from "bitcoin-ts-cashcontracts"
import * as cashcontracts from "cashcontracts-wasm"
import { List, Map } from "immutable"
import { Base64 } from 'js-base64'

export type TokenId = string

export const DUST_AMOUNT = 0x222

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

export class Wallet {
    public static debug: boolean
    private curve: bitcoin.Secp256k1
    private secret: Uint8Array
    private pubkey: Uint8Array
    private address: cashcontracts.Address
    private slpAddress: cashcontracts.Address
    private addressBase: string
    private wallet: cashcontracts.Wallet
    private incomingEventSource: EventSource
    private outgoingEventSource: EventSource
    private utxos: List<UtxoEntry>
    private tokenUtxos: Map<TokenId, List<SLPUtxoEntry>>
    private tokenDetailsMap: Map<TokenId, TokenDetails>
    
    private receivedTxListeners: (() => void)[]

    private constructor(curve: bitcoin.Secp256k1,
                        secret: Uint8Array,
                        pubkey: Uint8Array,
                        wallet: cashcontracts.Wallet,
                        address: cashcontracts.Address,
                        utxos: List<UtxoEntry>,
                        tokenUtxos: Map<string, List<SLPUtxoEntry>>,
                        tokenDetailsMap: Map<TokenId, TokenDetails>) {
        this.curve = curve
        this.secret = secret
        this.pubkey = pubkey
        this.address = address
        this.slpAddress = address.with_prefix("simpleledger")
        this.addressBase = address.cash_addr().substr(address.cash_addr().indexOf(':') + 1)
        this.wallet = wallet
        this.utxos = utxos
        this.tokenUtxos = tokenUtxos
        this.tokenDetailsMap = tokenDetailsMap
        this.receivedTxListeners = []
        this.incomingEventSource = this.createIncomingEventSource()
        this.outgoingEventSource = this.createOutgoingEventSource()
    }

    private createIncomingEventSource(): EventSource {
        const query = {
            "v": 3,
            "q": {
                "find": {"out.e.a": this.addressBase},
                "project": {
                    "txid": "$tx.h",
                    "out": "$out",
                },
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const source = new EventSource("https://bitsocket.org/s/" + queryBase64)
        source.onmessage = (msg) => this.receivedTx(msg)
        return source
    }

    private createOutgoingEventSource(): EventSource {
        const query = {
            "v": 3,
            "q": {
                "find": {"in.e.h": {
                    "$in": this.utxos.map(utxo => utxo.txid).toArray()
                }},
                "project": {
                    "txid": "$tx.h",
                    "out": "$out",
                },
            },
        }
        const queryBase64 = Base64.encode(JSON.stringify(query))
        const source = new EventSource("https://bitsocket.org/s/" + queryBase64)
        source.onmessage = (msg) => this.receivedTx(msg)
        return source
    }

    private static async fetchTokenUtxos(slpAddress: string): Promise<Map<string, List<SLPUtxoEntryRemote>>> {
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
            .groupBy((entry) => entry.tokenDetails.tokenIdHex)
            .map(utxos => utxos.toList())
            .toMap()
    }

    private static async fetchTokenDetails(tokenIds: List<TokenId>): Promise<Map<TokenId, TokenDetails>> {
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

    private static async fetchUtxos(address: string): Promise<List<UtxoEntry>> {
        const utxosJson: {utxos: UtxoEntry[]} = await (await fetch("https://rest.bitcoin.com/v2/address/utxo/" + address)).json()
        return List(utxosJson.utxos)
    }

    private static calculateBaseToken(utxosJsonByToken: Map<string, List<SLPUtxoEntryRemote>>,
                                      details: Map<string, TokenDetails>) {
        return utxosJsonByToken.map(utxos => utxos.map(utxo => {
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
        }))
    }

    private receivedTx(msg: MessageEvent) {
        if (Wallet.debug)
            console.log(msg)
        const resp: {data: ReceivedTx, type: string} = JSON.parse(msg.data)
        if (resp.type == 'open' || resp.type == 'block')
            return
        this.updateWallet().then(
            () => this.receivedTxListeners.forEach(listener => listener())
        )
    }

    public async updateWallet(): Promise<void> {
        this.utxos = await Wallet.fetchUtxos(this.address.cash_addr())
        const utxosJsonByToken = await Wallet.fetchTokenUtxos(this.slpAddress.cash_addr())
        this.tokenDetailsMap = await Wallet.fetchTokenDetails(utxosJsonByToken.keySeq().toList())
        this.tokenUtxos = Wallet.calculateBaseToken(utxosJsonByToken, this.tokenDetailsMap)
        this.outgoingEventSource.close()
        this.outgoingEventSource = this.createOutgoingEventSource()
    }

    public static async create(secret: Uint8Array): Promise<Wallet> {
        try {
            await cashcontracts.ready
            const curve = await bitcoin.instantiateSecp256k1()
            const pubkey = curve.derivePublicKeyCompressed(secret)
            const address = cashcontracts.Address.from_pub_key_hex("bitcoincash", "P2PKH", bufferToHex(pubkey))
            const wallet = cashcontracts.Wallet.from_cash_addr(address.cash_addr())
            const utxos = await Wallet.fetchUtxos(address.cash_addr())
            const utxosJsonByToken = await Wallet.fetchTokenUtxos(address.with_prefix("simpleledger").cash_addr())
            const tokenDetails = await Wallet.fetchTokenDetails(utxosJsonByToken.keySeq().toList())
            return new Wallet(
                curve,
                secret,
                pubkey,
                wallet,
                address,
                utxos,
                Wallet.calculateBaseToken(utxosJsonByToken, tokenDetails),
                tokenDetails,
            )
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

    public addReceivedTxListener(listener: () => void) {
        this.receivedTxListeners.push(listener)
    }

    public cashAddr(): string {
        return this.address.cash_addr()
    }

    public slpAddr(): string {
        return this.slpAddress.cash_addr()
    }

    public totalBalance(): number {
        return this.utxos
            .map((utxoEntry) => utxoEntry.satoshis)
            .reduce((a, b) => a + b, 0)
    }

    private nonTokenUtxos(): List<UtxoEntry> {
        return this.utxos
            .filterNot(utxo => 
                this.tokenUtxos.find(
                    (slpUtxos) => slpUtxos.find(slpUtxo => slpUtxo.txid == utxo.txid && slpUtxo.vout == utxo.vout) !== undefined
                ) !== undefined
            )
    }

    public nonTokenBalance(): number {
        return this.nonTokenUtxos()
            .map((utxoEntry) => utxoEntry.satoshis)
            .reduce((a, b) => a + b, 0)
    }

    public tokenIds(): List<string> {
        return this.tokenUtxos.keySeq().toList()
    }

    public tokenBalance(tokenId: TokenId): number {
        return this.tokenUtxos
            .get(tokenId, keyError(tokenId))
            .map(utxoEntry => parseFloat(utxoEntry.slpAmount))
            .reduce((a, b) => a + b, 0)
    }

    public tokenDetails(tokenId: TokenId): TokenDetails {
        return this.tokenDetailsMap.get(tokenId, keyError(tokenId))
    }

    public toTokenBaseAmount(tokenId: TokenId, amount: number): number {
        return amount * Math.pow(10, this.tokenDetailsMap.get(tokenId, keyError(tokenId)).decimals)
    }

    public initNonTokenTx(): UnsignedTx {
        const nonTokenUtxos = this.nonTokenUtxos().map(utxo => ({
            tx_id_hex: utxo.txid,
            vout: utxo.vout,
            amount: utxo.satoshis.toString(),
        }))
        return new UnsignedTx(
            this.curve,
            this.secret,
            this.pubkey,
            nonTokenUtxos.size,
            this.wallet.init_tx(nonTokenUtxos.toArray())
        )
    }

    public initTokenTx(tokenId: TokenId): UnsignedTokenTx {
        const nonTokenUtxos = this.nonTokenUtxos()
        const tokenUtxos = this.tokenUtxos.get(tokenId, keyError(tokenId))
        const tokenDetails = this.tokenDetailsMap.get(tokenId, keyError(tokenId))
        return new UnsignedTokenTx(
            this.curve,
            this.secret,
            this.pubkey,
            tokenDetails,
            tokenUtxos.map(utxo => utxo.slpBaseAmount).concat(nonTokenUtxos.map(() => 0)).toArray(),
            this.wallet.init_tx(
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
                    .toArray()
            ),
        )
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
    address: string
    bchSatoshis: number
    slpAmount: string
}

interface SLPUtxoEntry extends SLPUtxoEntryRemote {
    slpBaseAmount: number
    amountFactor: number
}

interface ReceivedTx {
    txid: string
    out: {
        e: {
            v: number
            i: number
            a: string
        }
    }[]
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
}
export type OutputType = P2PKH | P2SH | OpReturn | SLP | AdvancedTradeOffer

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

    addLeftoverOutput(address: string, feePerKb?: number): number | undefined {
        return this.unsignedTx.add_leftover_output(address, feePerKb)
    }

    sign(): Tx {
        const preImages: string[] = this.unsignedTx.pre_image_hashes()
        const signatures = preImages.map((hash, idx) => {
            return bufferToHex(this.curve.signMessageHashDER(this.inputSecrets[idx], hexToBuffer(hash)))
        })
        return new Tx(this.unsignedTx.sign(signatures, this.inputPubkeys.map(bufferToHex)))
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
            this.inputSecrets.push(this.pubkey)
        } else {
            this.inputSecrets.push(secret)
            this.inputPubkeys.push(this.curve.derivePublicKeyCompressed(secret))
        }
        this.tokenInputAmounts.push(tokenAmount * this.tokenFactor)
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

    sign(nonTokenAddress: string, tokenAddress: string, feePerKb?: number): Tx {
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
        this.unsignedTx.add_leftover_output(nonTokenAddress, feePerKb)
        const preImages: string[] = this.unsignedTx.pre_image_hashes()
        const signatures = preImages.map((hash, idx) => {
            return bufferToHex(this.curve.signMessageHashDER(this.inputSecrets[idx], hexToBuffer(hash)))
        })
        return new Tx(this.unsignedTx.sign(signatures, this.inputPubkeys.map(bufferToHex)))
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

export function createAdvancedTradeOfferTx(
        wallet: Wallet,
        tokenId: TokenId,
        sellAmountToken: number,
        price: number,
        receivingAddress: string): Tx {
    const txBuild = wallet.initTokenTx(tokenId)
    const basePrice = price / wallet.toTokenBaseAmount(tokenId, 1)
    const isInverted = basePrice < 1
    const scriptPrice = Math.round(isInverted ? 1.0 / basePrice : basePrice)
    const sellBaseAmount = wallet.toTokenBaseAmount(tokenId, sellAmountToken)
    txBuild.addTokenOutput(
        {
            type: "P2SH",
            output: {
                type: 'AdvancedTradeOffer',
                amount: DUST_AMOUNT.toString(),
                lokad_id: "EXCH",
                version: 2,
                power: 0,
                is_inverted: isInverted,
                token_id_hex: tokenId,
                token_type: 1,
                sell_amount_token: sellBaseAmount.toString(),
                price: scriptPrice.toString(),
                address: receivingAddress,
                spend_params: undefined,
            },
        },
        sellAmountToken,
    )
    return txBuild.sign(wallet.cashAddr(), wallet.slpAddr())
}
