package org.bitcoins.core.script.oracle
import akka.pattern.ask
import akka.util.Timeout
import akka.actor.{ActorRef, ActorSystem, PoisonPill}
import com.github.nfldb.config.NflDbApiDbConfigWorkstation
import com.github.nfldb.models.{PlayPlayerDAO, PlayPlayerPassing}
import org.bitcoins.core.script.ScriptProgram
import org.bitcoins.core.script.arithmetic._
import org.bitcoins.core.script.constant._
import org.joda.time.DateTime

import scala.concurrent.{Await, ExecutionContext, Future}
import scala.util.{Failure, Success}
import scala.concurrent.duration.DurationInt

/**
  * Created by chris on 2/1/17.
  */
trait OracleInterpreter {

  def opPassingYdsForGame(program: ScriptProgram) : ScriptProgram = {
    require(program.script.headOption == Some(OP_PASSINGYDS), "Next script operation must be OP_TICKERQUERY")
    require(program.stack.size > 3, "We require the stack to have a gameId, agreedYds, playerId, and predicate on the stack for OP_PASSINGYDS")
    val gameId: Long = parseGameId(program.stack(3))
    //TODO: We need to figure out a way to encode tickers
    val playerId: String = parsePlayerId(program.stack(2))
    val agreedYds = parseAgreedYds(program.stack(1))
    val predicate = parsePredicate(program.stack.head)
    //see this conversation between sipa and I why 'doubles' are a terrible idea in consensus critical code
    //this doesn't answer the question about arbitrary precision numbers though, especially ones that do not
    //hit the stack / blockchain
    //https://botbot.me/freenode/bitcoin-core-dev/2017-02-01/?tz=America/Chicago
    //TODO: Review comments above and consider converting to an integer type, but what does this mean for our oracles?
    //do they always have to return integers?
    val actualPassingYds: Long = queryPassingYds(playerId,gameId)

    val bool = executePredicate(predicate,agreedYds,actualPassingYds)
    val result = if (bool) OP_TRUE else OP_FALSE

    ScriptProgram(program, result :: program.stack.tail.tail.tail.tail, program.script.tail)
  }

  /** Parses a ticker from the given script token */
  private def parsePlayerId(token: ScriptToken): String = {
    val tokenWithoutPrefix = token match {
      case number: ScriptNumber => number.underlying
      case x @ (_: ScriptConstant | _: ScriptOperation) =>
        throw new IllegalArgumentException("NFL sidechain expects a number as the player id, got: " + x)
    }
    val neededDigits = 10

    val playerIdBeforePadding = "00-" + tokenWithoutPrefix
    val neededPadding = neededDigits - playerIdBeforePadding.size
    val padding = "0" * neededPadding
    "00-" + padding + tokenWithoutPrefix
  }

  /** Parses a time in seconds from the given [[ScriptToken]] */
  private def parseGameId(token: ScriptToken): Long = token match {
    case number: ScriptNumber => number.underlying
    case x @ (_: ScriptConstant | _: ScriptOperation) =>
      throw new IllegalArgumentException("OP_TICKERQUERY expects a number as the time, got: " + x)
  }

  /** Sends an http request to our oracle requesting the price of the given ticker at the given time */
  private def queryPassingYds(playerId: String, gameId: Long): Long = {
    val context = ActorSystem("bitcoin-s-system")
    val dbConfig = NflDbApiDbConfigWorkstation
    implicit val timeout = Timeout(5.seconds)
    val playDAO: ActorRef = PlayPlayerDAO(context, dbConfig)
    val gameIdString: String = gameId.toString
    val statsFuture: Future[Seq[PlayPlayerPassing]] = playDAO.ask(PlayPlayerDAO.PlayerPassingStatsForGameByID(gameIdString, playerId)).mapTo[Seq[PlayPlayerPassing]]
    killActorOnComplete(statsFuture, playDAO, context.dispatcher)
    val stats = Await.result(statsFuture,5.seconds)
    val stat = stats.head
    stat.passingYds
  }

  /** Parses the [[ArithmeticPredicateOperation]] from the given scriptToken */
  private def parsePredicate(token: ScriptToken): ArithmeticPredicateOperation = {
    //arithmetic predicate operations bytes
    val bytes: Seq[Seq[Byte]] = ArithmeticPredicateOperation.operations.map(_.bytes)
    val tokenBytes = token.bytes
    val predicateIndex = bytes.indexOf(tokenBytes)
    val predicate = if (predicateIndex == -1) {
      throw new IllegalArgumentException("Invalid ArithmeticPredicateOperation for OP_TICKERQUERY")
    } else ArithmeticPredicateOperation.operations(predicateIndex)
    predicate

  }
  /** Parses the agreed yards for the player from the given [[ScriptToken]] */
  private def parseAgreedYds(token: ScriptToken): Long = token match {
    case number: ScriptNumber => number.underlying
    case x @ (_: ScriptConstant | _ : ScriptOperation) =>
      throw new IllegalArgumentException("OP_TICKERQUERY expects a number as the agreed price, got: " + x)
  }

  /** Executes the given [[ArithmeticPredicateOperation]] between on the given agreedPrice and spotPrice */
  private def executePredicate(predicate: ArithmeticPredicateOperation, agreedPrice: Long,
                               spotPrice: BigDecimal): Boolean = predicate match {
    case OP_NUMEQUAL => spotPrice == agreedPrice
    case OP_NUMNOTEQUAL => spotPrice != agreedPrice
    case OP_GREATERTHAN => spotPrice > agreedPrice
    case OP_GREATERTHANOREQUAL => spotPrice >= agreedPrice
    case OP_LESSTHANOREQUAL => spotPrice <= agreedPrice
    case OP_LESSTHAN => spotPrice < agreedPrice
  }

  private def killActorOnComplete(f: Future[Any], actor: ActorRef, context: ExecutionContext): Unit = f.onComplete {
    case Success(_) | Failure(_) => actor ! PoisonPill
  }(context)
}

object OracleInterpreter extends OracleInterpreter
