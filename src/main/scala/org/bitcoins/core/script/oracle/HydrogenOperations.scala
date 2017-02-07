package org.bitcoins.core.script.oracle

import org.bitcoins.core.script.ScriptOperationFactory
import org.bitcoins.core.script.constant.ScriptOperation

/**
  * Created by chris on 2/1/17.
  */
sealed trait HydrogenOperation extends ScriptOperation

//replace OP_NOP4
case object OP_APIQUERY1ID extends HydrogenOperation {
  override def opCode = 179
}

object HydrogenOperation extends ScriptOperationFactory[HydrogenOperation] {
  override def operations = Seq(OP_APIQUERY1ID)
}