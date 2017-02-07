package org.bitcoins.core.script.oracle
import akka.actor.{ActorRef, PoisonPill}
import org.bitcoins.core.script.ScriptProgram
import org.bitcoins.core.script.constant._

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success}

/**
  * Created by chris on 2/1/17.
  */
trait HydrogenInterpreter {

  /** Takes the identifier and time from the stack then queries our oracle, finally pushes the result from the oracle onto the stack */
  def opApiQuery1Id(program: ScriptProgram) : ScriptProgram = {
    require(program.script.headOption == Some(OP_APIQUERY1ID), "Next script operation must be OP_APIQUERY1ID")
    require(program.stack.size > 1, "We require the stack to have a time and id for OP_APIQUERY1ID")
    val time: Long = parseTime(program.stack(1))
    val id: String = parseId(program.stack.head)
    val actualNum: Long = sendQuery(id,time)
    val result = ScriptNumber(actualNum)
    ScriptProgram(program, result :: program.stack.tail.tail, program.script.tail)
  }

  /** This function parses the unique identifier for the script, this identifier will be sent to the oracle
    * to retrieve information */
  def parseId(token: ScriptToken): String

  /** Sends an http request to our oracle requesting information about the given id at time t */
  def sendQuery(id: String, time: Long): Long

  /** Parses the number that the counter parties agreed to */
  def parseAgreedNumber(token: ScriptToken): Long

  /** Parses the agreed upon time from the given [[ScriptToken]] */
  def parseTime(token: ScriptToken): Long
}
