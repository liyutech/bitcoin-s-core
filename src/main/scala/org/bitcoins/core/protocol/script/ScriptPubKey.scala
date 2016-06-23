package org.bitcoins.core.protocol.script

import org.bitcoins.core.crypto.ECPublicKey
import org.bitcoins.core.serializers.script.{RawScriptPubKeyParser, ScriptParser}
import org.bitcoins.core.protocol._
import org.bitcoins.core.script.ScriptSettings
import org.bitcoins.core.script.bitwise.{OP_EQUAL, OP_EQUALVERIFY}
import org.bitcoins.core.script.constant._
import org.bitcoins.core.script.crypto.{OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_HASH160}
import org.bitcoins.core.script.stack.OP_DUP
import org.bitcoins.core.util.{BitcoinSLogger, BitcoinScriptUtil, CryptoUtil, Factory}

import scala.util.{Failure, Success, Try}

/**
 * Created by chris on 12/26/15.
 */
sealed trait ScriptPubKey extends NetworkElement with BitcoinSLogger {

  /**
   * Representation of a scriptSignature in a parsed assembly format
   * this data structure can be run through the script interpreter to
   * see if a script evaluates to true
    *
    * @return
   */
  lazy val asm : Seq[ScriptToken] = ScriptParser.fromBytes(bytes)

}

/**
 * Represents a pay-to-pubkey hash script pubkey
 * https://bitcoin.org/en/developer-guide#pay-to-public-key-hash-p2pkh
 * Format: OP_DUP OP_HASH160 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 */
trait P2PKHScriptPubKey extends ScriptPubKey


object P2PKHScriptPubKey extends Factory[P2PKHScriptPubKey] {
  override def fromBytes(bytes : Seq[Byte]): P2PKHScriptPubKey = {
    val scriptPubKey = RawScriptPubKeyParser.read(bytes)
    matchP2PKHScriptPubKey(scriptPubKey)
  }

  def apply(pubKey : ECPublicKey) = {
    val hash = CryptoUtil.ripeMd160(pubKey.bytes)
    val bytesToPushOntoStack = BytesToPushOntoStack(hash.bytes.size)
    val asm = Seq(OP_DUP, OP_HASH160, bytesToPushOntoStack,  ScriptConstant(hash.bytes), OP_EQUALVERIFY, OP_CHECKSIG)
    val scriptPubKey = ScriptPubKey.fromAsm(asm)
    matchP2PKHScriptPubKey(scriptPubKey)
  }

  private def matchP2PKHScriptPubKey(scriptPubKey: ScriptPubKey) = scriptPubKey match {
    case p2pkhScriptPubKey : P2PKHScriptPubKey => p2pkhScriptPubKey
    case x : ScriptPubKey => throw new IllegalArgumentException("Expected a p2pkh scriptPubKey, got: " + x)
  }
}
/**
 * Represents a multisignature script public key
 * https://bitcoin.org/en/developer-guide#multisig
 * Format: <m> <A pubkey> [B pubkey] [C pubkey...] <n> OP_CHECKMULTISIG
 */
trait MultiSignatureScriptPubKey extends ScriptPubKey {

  /**
    * Returns the amount of required signatures for this multisignature script pubkey output
    *
    * @return
    */
  def requiredSigs : Long = {
    val asmWithoutPushOps = asm.filterNot(_.isInstanceOf[BytesToPushOntoStack])
    val opCheckMultiSigIndex = if (asm.indexOf(OP_CHECKMULTISIG) != -1) asmWithoutPushOps.indexOf(OP_CHECKMULTISIG) else asmWithoutPushOps.indexOf(OP_CHECKMULTISIGVERIFY)
    logger.debug("opCheckMultiSigIndex: " + opCheckMultiSigIndex)
    logger.debug("maxSigs: " + maxSigs)
    logger.debug("asmWithoutPushOps: " + asmWithoutPushOps)
    //magic number 2 represents the maxSig operation and the OP_CHECKMULTISIG operation at the end of the asm
    val numSigsRequired = asmWithoutPushOps(opCheckMultiSigIndex - maxSigs.toInt - 2)
    numSigsRequired match {
      case x : ScriptNumber => x.num
      case _ => throw new RuntimeException("The first element of the multisignature pubkey must be a script number operation\n" +
        "operation: " + numSigsRequired +
        "\nscriptPubKey: " + this)
    }
  }

  /**
   * The maximum amount of signatures for this multisignature script pubkey output
    *
    * @return
   */
  def maxSigs : Long = {
    if (checkMultiSigIndex == -1 || checkMultiSigIndex == 0) {
      //means that we do not have a max signature requirement
      0.toLong
    } else {
      asm(checkMultiSigIndex - 1) match {
        case x : ScriptNumber => x.num
        case _ => throw new RuntimeException("The element preceding a OP_CHECKMULTISIG operation in a  multisignature pubkey must be a script number operation")
      }
    }
  }


  /**
   * Gives the OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY index inside of asm
    *
    * @return the index of OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY
   */
  private def checkMultiSigIndex : Int = {
    if (asm.indexOf(OP_CHECKMULTISIG) != -1) asm.indexOf(OP_CHECKMULTISIG) else asm.indexOf(OP_CHECKMULTISIGVERIFY)
  }

  /**
   * Returns the public keys encoded into the scriptPubKey
    *
    * @return
   */
  def publicKeys : Seq[ECPublicKey] = {
    asm.filter(_.isInstanceOf[ScriptConstant]).slice(1, maxSigs.toInt + 1).map(key => ECPublicKey(key.hex))
  }
}

object MultiSignatureScriptPubKey extends Factory[MultiSignatureScriptPubKey] with BitcoinSLogger {
  override def fromBytes(bytes : Seq[Byte]): MultiSignatureScriptPubKey = {
    val scriptPubKey = RawScriptPubKeyParser.read(bytes)
    matchMultiSigScriptPubKey(scriptPubKey)
  }

  def apply(requiredSigs : Int, pubKeys : Seq[ECPublicKey]): MultiSignatureScriptPubKey = {
    require(requiredSigs <= ScriptSettings.maxPublicKeysPerMultiSig, "We cannot have more required signatures than: " +
      ScriptSettings.maxPublicKeysPerMultiSig + " got: " + requiredSigs)
    require(pubKeys.length <= ScriptSettings.maxPublicKeysPerMultiSig, "We cannot have more public keys than " +
      ScriptSettings.maxPublicKeysPerMultiSig + " got: " + pubKeys.length)

    val required = ScriptNumberOperation.fromNumber(requiredSigs) match {
      case Some(scriptNumOp) => Seq(scriptNumOp)
      case None =>
        val scriptNum = ScriptNumber(requiredSigs)
        Seq(BytesToPushOntoStack(scriptNum.bytes.length), scriptNum)
    }
    val possible = ScriptNumberOperation.fromNumber(pubKeys.length) match {
      case Some(scriptNumOp) => Seq(scriptNumOp)
      case None =>
        val scriptNum = ScriptNumber(pubKeys.length)
        Seq(BytesToPushOntoStack(scriptNum.bytes.length), scriptNum)
    }
    val pubKeysWithPushOps : Seq[Seq[ScriptToken]] = for {
      pubKey <- pubKeys
      pushOp = BytesToPushOntoStack(pubKey.bytes.length)
      constant = ScriptConstant(pubKey.bytes)
    } yield Seq(pushOp, constant)


    val asm = required ++ pubKeysWithPushOps.flatten ++ possible ++ Seq(OP_CHECKMULTISIG)
    logger.info("Asm created by multisignature companion object: " + asm)
    val scriptPubKey = ScriptPubKey.fromAsm(asm)
    matchMultiSigScriptPubKey(scriptPubKey)
  }

  private def matchMultiSigScriptPubKey(scriptPubKey: ScriptPubKey): MultiSignatureScriptPubKey = scriptPubKey match {
    case multiSigScriptPubKey : MultiSignatureScriptPubKey => multiSigScriptPubKey
    case x : ScriptPubKey => throw new IllegalArgumentException("Exepected multisignature scriptPubKey, got: " + x)
  }
}

/**
 * Represents a pay-to-scripthash public key
 * https://bitcoin.org/en/developer-guide#pay-to-script-hash-p2sh
 * Format: OP_HASH160 <Hash160(redeemScript)> OP_EQUAL
 */
trait P2SHScriptPubKey extends ScriptPubKey

/**
 * Represents a pay to public key script public key
 * https://bitcoin.org/en/developer-guide#pubkey
 * Format: <pubkey> OP_CHECKSIG
 */
trait P2PKScriptPubKey extends ScriptPubKey {
  def publicKey = ECPublicKey(BitcoinScriptUtil.filterPushOps(asm).head.bytes)
}

object P2PKScriptPubKey extends Factory[P2PKScriptPubKey] {
  override def fromBytes(bytes : Seq[Byte]) = {
    val scriptPubKey = RawScriptPubKeyParser.read(bytes)
    matchP2PKScriptPubKey(scriptPubKey)
  }

  def apply(pubKey : ECPublicKey): P2PKScriptPubKey = {
    val bytesToPushOntoStack = BytesToPushOntoStack(pubKey.bytes.size)
    val asm = Seq(bytesToPushOntoStack, ScriptConstant(pubKey.bytes), OP_CHECKSIG)
    val scriptPubKey = ScriptPubKey.fromAsm(asm)
    matchP2PKScriptPubKey(scriptPubKey)
  }

  private def matchP2PKScriptPubKey(scriptPubKey: ScriptPubKey) = scriptPubKey match {
    case p2pkScriptPubKey : P2PKScriptPubKey => p2pkScriptPubKey
    case x : ScriptPubKey => throw new IllegalArgumentException("Must match a p2pk scriptPubkey inside of this function, got: " + x)
  }
}

trait NonStandardScriptPubKey extends ScriptPubKey

/**
 * Represents the empty script pub key
 */
case object EmptyScriptPubKey extends ScriptPubKey {
  def hex = ""
}

/**
  * Factory companion object used to create ScriptPubKey objects
  */
object ScriptPubKey extends Factory[ScriptPubKey] with BitcoinSLogger {
  def empty : ScriptPubKey = fromAsm(List())

  private case class P2PKScriptPubKeyImpl(hex : String) extends P2PKScriptPubKey

  private case class NonStandardScriptPubKeyImpl(hex : String) extends NonStandardScriptPubKey

  private case class P2PKHScriptPubKeyImpl(hex : String) extends P2PKHScriptPubKey

  private case class MultiSignatureScriptPubKeyImpl(hex : String) extends MultiSignatureScriptPubKey

  private case class P2SHScriptPubKeyImpl(hex : String) extends P2SHScriptPubKey

  /**
    * Creates a scriptPubKey from its asm representation
    *
    * @param asm
    * @return
    */
  def fromAsm(asm : Seq[ScriptToken]) : ScriptPubKey = {
    val scriptPubKeyHex = BitcoinScriptUtil.asmToHex(asm)
    asm match {
      case Seq() => EmptyScriptPubKey
      case List(OP_DUP, OP_HASH160, x : BytesToPushOntoStack, y : ScriptConstant, OP_EQUALVERIFY, OP_CHECKSIG) =>
        P2PKHScriptPubKeyImpl(scriptPubKeyHex)
      case List(OP_HASH160, x : BytesToPushOntoStack, y : ScriptConstant, OP_EQUAL) =>
        P2SHScriptPubKeyImpl(scriptPubKeyHex)
      case List(b : BytesToPushOntoStack, x : ScriptConstant, OP_CHECKSIG) => P2PKScriptPubKeyImpl(scriptPubKeyHex)
      case _ if (isMultiSignatureScriptPubKey(asm)) =>
        MultiSignatureScriptPubKeyImpl(scriptPubKeyHex)
      case _ => NonStandardScriptPubKeyImpl(scriptPubKeyHex)
    }
  }

  /**
    * Determines if the given script tokens are a multisignature scriptPubKey
    *
    * @param asm the tokens to check
    * @return a boolean indicating if the given tokens are a multisignature scriptPubKey
    */
  private def isMultiSignatureScriptPubKey(asm : Seq[ScriptToken]) : Boolean = {

    val isNotEmpty = asm.size > 0
    val containsMultSigOp = asm.contains(OP_CHECKMULTISIG) || asm.contains(OP_CHECKMULTISIGVERIFY)
    //we need either the first or second asm operation to indicate how many signatures are required
    val hasRequiredSignaturesTry = Try {
      asm.headOption match {
        case None => false
        case Some(token) =>
          //this is for the case that we have more than 16 public keys, the
          //first operation will be a push op, the second operation being the actual number of keys
          if (token.isInstanceOf[BytesToPushOntoStack]) isValidPubKeyNumber(asm.tail.head)
          else isValidPubKeyNumber(token)
      }
    }
    //the second to last asm operation should be the maximum amount of public keys
    val hasMaximumSignaturesTry = Try {
      asm(asm.length - 2) match {
        case token: ScriptToken => isValidPubKeyNumber(token)
      }
    }

    val standardOps = asm.filter(op =>  op.isInstanceOf[ScriptNumber] || op == OP_CHECKMULTISIG ||
      op == OP_CHECKMULTISIGVERIFY || op.isInstanceOf[ScriptConstant] || op.isInstanceOf[BytesToPushOntoStack])
    logger.info("Non standard ops: " + standardOps)
    (hasRequiredSignaturesTry, hasMaximumSignaturesTry) match {
      case (Success(hasRequiredSignatures), Success(hasMaximumSignatures)) =>
        logger.info("Has required signatures: " + hasRequiredSignatures)
        logger.info("Has maximum signatures: " + hasMaximumSignatures)
        val result = isNotEmpty && containsMultSigOp && hasRequiredSignatures && hasMaximumSignatures && standardOps.size == asm.size
        logger.info("Result: " + result)
        result
      case (Success(_), Failure(_)) => false
      case (Failure(_), Success(_)) => false
      case (Failure(_), Failure(_)) => false
    }
  }

  /**
    * Checks that the given script token is with the range of the maximum amount of
    * public keys we can have in a [[MultiSignatureScriptPubKey]]
    *
    * @param token
    * @return
    */
  private def isValidPubKeyNumber(token : ScriptToken): Boolean = token match {
    case constant : ScriptConstant =>
      constant.isInstanceOf[ScriptNumber] ||
        ScriptNumber(constant.bytes) <= ScriptNumber(ScriptSettings.maxPublicKeysPerMultiSig)
    case _ : ScriptToken => false
  }
  def fromBytes(bytes : Seq[Byte]) : ScriptPubKey = RawScriptPubKeyParser.read(bytes)

}