package org.bitcoins.core.protocol.script

import org.bitcoins.core.crypto.{ECPublicKey, Sha256Digest, Sha256Hash160Digest}
import org.bitcoins.core.protocol.CompactSizeUInt
import org.bitcoins.core.script.constant.{ScriptConstant, ScriptToken}
import org.bitcoins.core.script.result._
import org.bitcoins.core.util.{BitcoinSLogger, BitcoinSUtil, CryptoUtil}

/**
  * Created by chris on 11/10/16.
  */
sealed trait WitnessVersion extends BitcoinSLogger {
  /** Rebuilds the full script from the given witness and [[ScriptPubKey]]
    * Either returns the stack and the [[ScriptPubKey]] it needs to be executed against or
    * the [[ScriptError]] that was encountered while rebuilding the witness*/
  def rebuild(scriptWitness: ScriptWitness, witnessProgram: Seq[ScriptToken]): Either[(Seq[ScriptToken], ScriptPubKey),ScriptError]
}

case object WitnessVersion0 extends WitnessVersion {

  override def rebuild(scriptWitness: ScriptWitness, witnessProgram: Seq[ScriptToken]): Either[(Seq[ScriptToken], ScriptPubKey),ScriptError] = {
    val programBytes = witnessProgram.flatMap(_.bytes)
    programBytes.size match {
      case 20 =>
        //p2wpkh
        if (scriptWitness.stack.size != 2) Right(ScriptErrorWitnessProgramMisMatch)
        else {
          val hash = Sha256Hash160Digest(programBytes)
          Left((scriptWitness.stack.map(ScriptConstant(_)), P2PKHScriptPubKey(hash)))
        }
      case 32 =>
        logger.info("Script witness stack: " + scriptWitness)
        //p2wsh
        if (scriptWitness.stack.isEmpty) Right(ScriptErrorWitnessProgramWitnessEmpty)
        else {
          //need to check if the hashes match
          val stackTop = scriptWitness.stack.head
          val stackHash = CryptoUtil.sha256(stackTop)
          logger.debug("Stack top: " + BitcoinSUtil.encodeHex(stackTop))
          logger.debug("Stack hash: " + stackHash)
          logger.debug("Witness program: " + witnessProgram)
          if (stackHash != Sha256Digest(witnessProgram.head.bytes)) Right(ScriptErrorWitnessProgramMisMatch)
          else {
            val compactSizeUInt = CompactSizeUInt.calculateCompactSizeUInt(stackTop)
            val scriptPubKey = ScriptPubKey(compactSizeUInt.bytes ++ stackTop)
            logger.debug("Script pub key for p2wsh: " + scriptPubKey.asm)
            val stack = scriptWitness.stack.tail.map(ScriptConstant(_))
            Left(stack, scriptPubKey)
          }
        }
      case _ =>
        logger.error("Invalid witness program length for witness version 0, got: " + programBytes.size)
        logger.error("Witness: " + scriptWitness)
        logger.error("Witness program: " + witnessProgram)
        //witness version 0 programs need to be 20 bytes or 32 bytes in size
        Right(ScriptErrorWitnessProgramWrongLength)
    }
  }
}

/** The witness version that represents all witnesses that have not been allocated yet */
case object UnassignedWitness extends WitnessVersion {
  override def rebuild(scriptWitness: ScriptWitness, witnessProgram: Seq[ScriptToken]): Either[(Seq[ScriptToken], ScriptPubKey),ScriptError] =
    Right(ScriptErrorDiscourageUpgradeableWitnessProgram)
}

object WitnessVersion {
  def apply(num: Long): WitnessVersion = num match {
    case 0 => WitnessVersion0
    case _ => UnassignedWitness
  }
}