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

        return encoded.reverse().toString()
    }

    fun decode(input: String): ByteArray {
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

        return ByteArray(zeros) { 0 } + decoded.reversed().toByteArray()
    }

    fun decodeChecked(input: String): ByteArray {
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

        return data
    }

    fun encodeChecked(input: ByteArray): String {
        val checksum = input.sha256().sha256().copyOfRange(0, CHECKSUM_LENGTH)
        return encode(input + checksum)
    }

    fun generatePepecoinAddress(publicKey: ByteArray): String {
        // Step 1: Perform SHA-256 and RIPEMD-160 on the public key
        val sha256Hash = publicKey.sha256()
        val ripemd160Hash = ripemd160(sha256Hash)

        // Step 2: Add Pepecoin prefix (Ensure this is correct, e.g., 0x37 for 'P')
        val addressPayload = byteArrayOf(0x37.toByte()) + ripemd160Hash

        // Step 3: Encode the result with Base58Check encoding (add checksum)
        return Base58.encodeChecked(addressPayload)
    }

    private fun ripemd160(input: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("RIPEMD160", BouncyCastleProvider())
        return digest.digest(input)
    }

    private fun ByteArray.sha256(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(this)
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
        dbPath = "$path/padawanDB_$PERSISTENCE_VERSION.sqlite3"
        dbConnection = Connection(dbPath)
    }

    fun createWallet() {
        val mnemonic = Mnemonic(WordCount.WORDS12)
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
    }


    private fun initialize(descriptor: Descriptor, changeDescriptor: Descriptor) {
        wallet = org.bitcoindevkit.Wallet(
            descriptor,
            changeDescriptor,
            Network.BITCOIN,
            dbConnection
        )
    }

    fun loadWallet() {
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
    }

    fun recoverWallet(recoveryPhrase: String) {
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
    }

    private fun fullScan() {
        val fullScanRequest = wallet.startFullScan().build()

        try {
            val update: Update = blockchainClient.fullScan(
                fullScanRequest = fullScanRequest,
                stopGap = 20u,
                batchSize = 10u,
                fetchPrevTxouts = true
            )
            wallet.applyUpdate(update)
            wallet.persist(dbConnection)
        } catch (e: ElectrumException) {
            Log.e(TAG, "ElectrumException during full scan: ${e.message}")
        }
    }

    fun sync() {
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
                wallet.applyUpdate(update)
                wallet.persist(dbConnection)
            } catch (e: ElectrumException) {
                Log.e(TAG, "ElectrumException during sync: ${e.message}")
            }
        }
    }

    fun getBalance(): ULong {
        return wallet.balance().total.toSat()
    }

    data class AddressInfo(
        val address: String,
        val index: Int
    )

    fun getLastUnusedAddress(): AddressInfo {
        // Retrieve the next address from the wallet
        val addressInfo = wallet.revealNextAddress(KeychainKind.EXTERNAL)

        // Convert the address to a Pepecoin address
        val publicKey = addressInfo.address.toString().toByteArray() // You can extract the public key from the address if needed
        val pepecoinAddress = Base58.generatePepecoinAddress(publicKey) // Generate Pepecoin address

        // Get the index of the address
        val index = addressInfo.index.toInt()

        return AddressInfo(pepecoinAddress, index)
    }

    fun createPsbt(recipientAddress: String, amount: Amount, feeRate: FeeRate): Psbt {
        val recipientScriptPubKey = Address(recipientAddress, Network.BITCOIN).scriptPubkey()
        return TxBuilder()
            .addRecipient(recipientScriptPubKey, amount)
            .feeRate(feeRate)
            .finish(wallet)
    }

    fun sign(psbt: Psbt) {
        wallet.sign(psbt)
    }

    fun listTransactions(): List<TransactionDetails> {
        val transactions = wallet.transactions()
        return transactions.map { tx ->
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
    }

    fun getTransaction(txid: String): TransactionDetails? {
        val allTransactions = listTransactions()
        allTransactions.forEach {
            if (it.txid == txid) {
                return it
            }
        }
        return null
    }

    fun broadcast(tx: Transaction): String {
        blockchainClient.broadcast(tx)
        return tx.computeTxid()
    }
}
