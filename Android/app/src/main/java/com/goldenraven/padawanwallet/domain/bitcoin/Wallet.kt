/*
 * Copyright 2020-2024 thunderbiscuit and contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE file.
 */

package com.goldenraven.padawanwallet.domain.bitcoin

import android.util.Log
import com.goldenraven.padawanwallet.utils.RequiredInitialWalletData
import com.goldenraven.padawanwallet.utils.TxType
import com.goldenraven.padawanwallet.utils.txType
import org.bitcoindevkit.Address
import org.bitcoindevkit.AddressInfo
import org.bitcoindevkit.Connection
import org.bitcoindevkit.ChainPosition as BdkChainPosition
import org.rustbitcoin.bitcoin.Amount
import org.bitcoindevkit.Descriptor
import org.bitcoindevkit.DescriptorSecretKey
import org.bitcoindevkit.ElectrumClient
import org.bitcoindevkit.ElectrumException
import org.rustbitcoin.bitcoin.FeeRate
import org.bitcoindevkit.KeychainKind
import org.bitcoindevkit.Mnemonic
import org.rustbitcoin.bitcoin.Network
import org.bitcoindevkit.Psbt
import org.bitcoindevkit.Transaction
import org.bitcoindevkit.TxBuilder
import org.bitcoindevkit.Update
import org.bitcoindevkit.WordCount
import java.math.BigInteger
import java.security.MessageDigest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

private const val TAG = "WalletObject"
private const val BITCOIN_ELECTRUM_URL: String = "ssl://electrum.pepelum.site:50002"
const val PERSISTENCE_VERSION = "V1"

object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private const val CHECKSUM_LENGTH = 4
    private const val BASE = ALPHABET.length
    private val INDEXES = IntArray(128) { -1 }

    init {
        for (i in ALPHABET.indices) {
            INDEXES[ALPHABET[i].code] = i
        }

        // Add BouncyCastle provider for RIPEMD160
        Security.addProvider(BouncyCastleProvider())
    }

    fun encode(input: ByteArray): String {
        Log.i(TAG, "Base58.encode: Start - Input: ${input.joinToString(", ")}")
        var zeros = 0
        for (byte in input) {
            if (byte.toInt() == 0) zeros++ else break
        }

        val encoded = StringBuilder()
        var num = input.fold(0.toBigInteger()) { acc, byte ->
            acc.shiftLeft(8) + (byte.toInt() and 0xFF).toBigInteger()
        }

        while (num > BigInteger.ZERO) {
            val rem = num % BASE.toBigInteger()
            encoded.append(ALPHABET[rem.toInt()])
            num /= BASE.toBigInteger()
        }

        repeat(zeros) {
            encoded.append('1')
        }

        val result = encoded.reverse().toString()
        Log.i(TAG, "Base58.encode: End - Encoded: $result")
        return result
    }

    fun decode(input: String): ByteArray {
        Log.i(TAG, "Base58.decode: Start - Input: $input")
        var zeros = 0
        for (char in input) {
            if (char == '1') zeros++ else break
        }

        var num = input.fold(BigInteger.ZERO) { acc, char ->
            acc * BASE.toBigInteger() + (INDEXES[char.code].takeIf { it >= 0 }
                ?: throw IllegalArgumentException("Invalid Base58 character: $char")).toBigInteger()
        }

        val decoded = mutableListOf<Byte>()
        while (num > BigInteger.ZERO) {
            decoded.add((num and 0xFF.toBigInteger()).toByte())
            num = num shr 8
        }

        val result = ByteArray(zeros) { 0 } + decoded.reversed().toByteArray()
        Log.i(TAG, "Base58.decode: End - Decoded: ${result.joinToString(", ")}")
        return result
    }

    fun decodeChecked(input: String): ByteArray {
        Log.i(TAG, "Base58.decodeChecked: Start - Input: $input")
        val dataWithChecksum = decode(input)
        if (dataWithChecksum.size < CHECKSUM_LENGTH) {
            throw IllegalArgumentException("Base58 input too short for checksum")
        }

        val data = dataWithChecksum.copyOfRange(0, dataWithChecksum.size - CHECKSUM_LENGTH)
        val checksum = dataWithChecksum.copyOfRange(dataWithChecksum.size - CHECKSUM_LENGTH, dataWithChecksum.size)

        val computedChecksum = data.sha256().sha256().copyOfRange(0, CHECKSUM_LENGTH)
        if (!computedChecksum.contentEquals(checksum)) {
            throw IllegalArgumentException("Invalid checksum")
        }

        Log.i(TAG, "Base58.decodeChecked: End - Data: ${data.joinToString(", ")}")
        return data
    }

    fun encodeChecked(input: ByteArray): String {
        Log.i(TAG, "Base58.encodeChecked: Start - Input: ${input.joinToString(", ")}")
        val checksum = input.sha256().sha256().copyOfRange(0, CHECKSUM_LENGTH)
        val result = encode(input + checksum)
        Log.i(TAG, "Base58.encodeChecked: End - Encoded: $result")
        return result
    }

    fun generatePepecoinAddress(publicKey: ByteArray): String {
        Log.i(TAG, "Base58.generatePepecoinAddress: Start - PublicKey: ${publicKey.joinToString(", ")}")
        // Step 1: Perform SHA-256 and RIPEMD-160 on the public key
        val sha256Hash = publicKey.sha256()
        Log.i(TAG, "SHA-256 Hash: ${sha256Hash.joinToString(", ")}")
        val ripemd160Hash = ripemd160(sha256Hash)
        Log.i(TAG, "RIPEMD-160 Hash: ${ripemd160Hash.joinToString(", ")}")

        // Step 2: Add Pepecoin prefix (Ensure this is correct, e.g., 0x37 for 'P')
        val addressPayload = byteArrayOf(0x37.toByte()) + ripemd160Hash
        Log.i(TAG, "Address Payload: ${addressPayload.joinToString(", ")}")

        // Step 3: Encode the result with Base58Check encoding (add checksum)
        val result = Base58.encodeChecked(addressPayload)
        Log.i(TAG, "Base58.generatePepecoinAddress: End - Pepecoin Address: $result")
        return result
    }

    private fun ripemd160(input: ByteArray): ByteArray {
        Log.i(TAG, "Base58.ripemd160: Start - Input: ${input.joinToString(", ")}")
        val digest = MessageDigest.getInstance("RIPEMD160", BouncyCastleProvider())
        val result = digest.digest(input)
        Log.i(TAG, "Base58.ripemd160: End - Result: ${result.joinToString(", ")}")
        return result
    }

    private fun ByteArray.sha256(): ByteArray {
        Log.i(TAG, "Base58.sha256: Start - Input: ${this.joinToString(", ")}")
        val digest = MessageDigest.getInstance("SHA-256")
        val result = digest.digest(this)
        Log.i(TAG, "Base58.sha256: End - Result: ${result.joinToString(", ")}")
        return result
    }

}

object Wallet {
    private lateinit var wallet: org.bitcoindevkit.Wallet
    private lateinit var dbPath: String
    private lateinit var dbConnection: Connection

    private val blockchainClient: ElectrumClient by lazy {
        Log.i(TAG, "Connecting to Electrum server at $BITCOIN_ELECTRUM_URL")
        ElectrumClient(BITCOIN_ELECTRUM_URL)
    }

    private var fullScanRequired: Boolean = !WalletRepository.isFullScanCompleted()

    // Setting the path requires the application context and is done once by PadawanWalletApplication
    fun setPathAndConnectDb(path: String) {
        Log.i(TAG, "Wallet.setPathAndConnectDb: Start - Path: $path")
        dbPath = "$path/padawanDB_$PERSISTENCE_VERSION.sqlite3"
        dbConnection = Connection(dbPath)
        Log.i(TAG, "Wallet.setPathAndConnectDb: End - DB Path: $dbPath")
    }

    fun createWallet() {
        Log.i(TAG, "Wallet.createWallet: Start")
        val mnemonic = Mnemonic(WordCount.WORDS12)
        Log.i(TAG, "Generated Mnemonic: ${mnemonic.toString()}")
        val bip32ExtendedRootKey = DescriptorSecretKey(Network.BITCOIN, mnemonic, null)
        val descriptor: Descriptor =
            Descriptor.newBip44(bip32ExtendedRootKey, KeychainKind.EXTERNAL, Network.BITCOIN)
        val changeDescriptor: Descriptor =
            Descriptor.newBip44(bip32ExtendedRootKey, KeychainKind.INTERNAL, Network.BITCOIN)

        initialize(descriptor, changeDescriptor)
        WalletRepository.saveWallet(
            dbPath,
            descriptor.toStringWithSecret(),
            changeDescriptor.toStringWithSecret()
        )
        WalletRepository.saveMnemonic(mnemonic.toString())
        Log.i(TAG, "Wallet.createWallet: End")
    }

    private fun initialize(descriptor: Descriptor, changeDescriptor: Descriptor) {
        Log.i(TAG, "Wallet.initialize: Start - Descriptor: ${descriptor.toStringWithSecret()} - Change Descriptor: ${changeDescriptor.toStringWithSecret()}")
        wallet = org.bitcoindevkit.Wallet(
            descriptor,
            changeDescriptor,
            Network.BITCOIN,
            dbConnection
        )
        Log.i(TAG, "Wallet.initialize: End")
    }

    fun loadWallet() {
        Log.i(TAG, "Wallet.loadWallet: Start")
        val initialWalletData: RequiredInitialWalletData = WalletRepository.getInitialWalletData()
        Log.i(TAG, "Loading existing wallet with descriptor: ${initialWalletData.descriptor}")
        Log.i(TAG, "Loading existing wallet with change descriptor: ${initialWalletData.changeDescriptor}")
        val descriptor = Descriptor(initialWalletData.descriptor, Network.BITCOIN)
        val changeDescriptor = Descriptor(initialWalletData.changeDescriptor, Network.BITCOIN)

        wallet = org.bitcoindevkit.Wallet.load(
            descriptor,
            changeDescriptor,
            dbConnection,
        )
        Log.i(TAG, "Wallet.loadWallet: End")
    }

    fun recoverWallet(recoveryPhrase: String) {
        Log.i(TAG, "Wallet.recoverWallet: Start - Recovery Phrase: $recoveryPhrase")
        val mnemonic = Mnemonic.fromString(recoveryPhrase)
        val bip32ExtendedRootKey = DescriptorSecretKey(Network.BITCOIN, mnemonic, null)
        val descriptor: Descriptor =
            Descriptor.newBip44(bip32ExtendedRootKey, KeychainKind.EXTERNAL, Network.BITCOIN)
        val changeDescriptor: Descriptor =
            Descriptor.newBip44(bip32ExtendedRootKey, KeychainKind.INTERNAL, Network.BITCOIN)

        initialize(descriptor, changeDescriptor)
        WalletRepository.saveWallet(
            dbPath,
            descriptor.toStringWithSecret(),
            changeDescriptor.toStringWithSecret()
        )
        WalletRepository.saveMnemonic(mnemonic.toString())
        Log.i(TAG, "Wallet.recoverWallet: End")
    }

    private fun fullScan() {
        Log.i(TAG, "Wallet.fullScan: Start")
        val fullScanRequest = wallet.startFullScan().build()

        try {
            val update: Update = blockchainClient.fullScan(
                fullScanRequest = fullScanRequest,
                stopGap = 20u,
                batchSize = 10u,
                fetchPrevTxouts = true
            )
            Log.i(TAG, "Full Scan Update: $update")
            wallet.applyUpdate(update)
            wallet.persist(dbConnection)
        } catch (e: ElectrumException) {
            Log.e(TAG, "ElectrumException during full scan: ${e.message}")
        }
        Log.i(TAG, "Wallet.fullScan: End")
    }

    fun sync() {
        Log.i(TAG, "Wallet.sync: Start")
        if (fullScanRequired) {
            Log.i(TAG, "Full scan required")
            fullScan()
            WalletRepository.fullScanCompleted()
            fullScanRequired = false
        } else {
            Log.i(TAG, "Just a normal sync!")
            val syncRequest = wallet.startSyncWithRevealedSpks().build()

            try {
                val update = blockchainClient.sync(
                    syncRequest = syncRequest,
                    batchSize = 10u,
                    fetchPrevTxouts = true
                )
                Log.i(TAG, "Sync Update: $update")
                wallet.applyUpdate(update)
                wallet.persist(dbConnection)
            } catch (e: ElectrumException) {
                Log.e(TAG, "ElectrumException during sync: ${e.message}")
            }
        }
        Log.i(TAG, "Wallet.sync: End")
    }

    fun getBalance(): ULong {
        Log.i(TAG, "Wallet.getBalance: Start")
        val result = wallet.balance().total.toSat()
        Log.i(TAG, "Wallet.getBalance: End - Balance: $result")
        return result
    }

    data class AddressInfo(
        val address: String,
        val index: Int
    )

    fun getLastUnusedAddress(): AddressInfo {
        Log.i(TAG, "Wallet.getLastUnusedAddress: Start")
        // Retrieve the next address from the wallet
        val addressInfo = wallet.revealNextAddress(KeychainKind.EXTERNAL)
        Log.i(TAG, "Retrieved Address Info: $addressInfo")

        // Convert the address to a Pepecoin address
        val publicKey = addressInfo.address.toString().toByteArray() // You can extract the public key from the address if needed
        Log.i(TAG, "Public Key: ${publicKey.joinToString(", ")}")
        val pepecoinAddress = Base58.generatePepecoinAddress(publicKey) // Generate Pepecoin address
        Log.i(TAG, "Generated Pepecoin Address: $pepecoinAddress")

        // Get the index of the address
        val index = addressInfo.index.toInt()
        val result = AddressInfo(pepecoinAddress, index)
        Log.i(TAG, "Wallet.getLastUnusedAddress: End - Result: $result")
        return result
    }

    fun createPsbt(recipientAddress: String, amount: Amount, feeRate: FeeRate): Psbt {
        Log.i(TAG, "Wallet.createPsbt: Start - Recipient Address: $recipientAddress, Amount: $amount, FeeRate: $feeRate")
        val recipientScriptPubKey = Address(recipientAddress, Network.BITCOIN).scriptPubkey()
        val result = TxBuilder()
            .addRecipient(recipientScriptPubKey, amount)
            .feeRate(feeRate)
            .finish(wallet)
        Log.i(TAG, "Wallet.createPsbt: End - Result: $result")
        return result
    }

    fun sign(psbt: Psbt) {
        Log.i(TAG, "Wallet.sign: Start - PSBT: $psbt")
        wallet.sign(psbt)
        Log.i(TAG, "Wallet.sign: End")
    }

    fun listTransactions(): List<TransactionDetails> {
        Log.i(TAG, "Wallet.listTransactions: Start")
        val transactions = wallet.transactions()
        val result = transactions.map { tx ->
            val (sent, received) = wallet.sentAndReceived(tx.transaction)
            val fee = wallet.calculateFee(tx.transaction)
            val feeRate = wallet.calculateFeeRate(tx.transaction)
            val txType: TxType = txType(sent = sent.toSat(), received = received.toSat())
            val chainPosition: ChainPosition = when (val position = tx.chainPosition) {
                is BdkChainPosition.Unconfirmed -> ChainPosition.Unconfirmed
                is BdkChainPosition.Confirmed -> ChainPosition.Confirmed(
                    position.confirmationBlockTime.blockId.height,
                    position.confirmationBlockTime.confirmationTime
                )
            }

            TransactionDetails(
                txid = tx.transaction.computeTxid(),
                sent = sent,
                received = received,
                fee = fee,
                feeRate = feeRate,
                txType = txType,
                chainPosition = chainPosition
            )
        }
        Log.i(TAG, "Wallet.listTransactions: End - Result: $result")
        return result
    }

    fun getTransaction(txid: String): TransactionDetails? {
        Log.i(TAG, "Wallet.getTransaction: Start - TXID: $txid")
        val allTransactions = listTransactions()
        allTransactions.forEach {
            if (it.txid == txid) {
                Log.i(TAG, "Wallet.getTransaction: End - Found Transaction: $it")
                return it
            }
        }
        Log.i(TAG, "Wallet.getTransaction: End - Transaction Not Found")
        return null
    }

    fun broadcast(tx: Transaction): String {
        Log.i(TAG, "Wallet.broadcast: Start - Transaction: $tx")
        blockchainClient.broadcast(tx)
        val result = tx.computeTxid()
        Log.i(TAG, "Wallet.broadcast: End - TXID: $result")
        return result
    }
}