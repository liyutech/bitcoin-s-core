package org.bitcoins.core.crypto

import org.bitcoinj.core.ECKey.ECDSASignature
import org.bitcoinj.core.Sha256Hash
import org.bitcoins.core.util.{BitcoinSLogger, BitcoinSUtil}
import org.scalatest.{FlatSpec, MustMatchers}
/**
 * Created by chris on 2/29/16.
 */
class BaseECKeyTest extends FlatSpec with MustMatchers {

  "BaseECKey" must "sign a arbitrary piece of data" in {
    //follows this bitcoinj test case
    //https://github.com/bitcoinj/bitcoinj/blob/master/core/src/test/java/org/bitcoinj/core/ECKeyTest.java#L110
    val privateKeyHex = "180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19"
    val key : BaseECKey = BaseECKey(privateKeyHex)
    val hash = DoubleSha256Digest(Sha256Hash.ZERO_HASH.getBytes.toSeq)
    val signature : ECDigitalSignature = key.sign(hash)

    val bitcoinjKey = org.bitcoinj.core.ECKey.fromPrivate(BitcoinSUtil.decodeHex(privateKeyHex).toArray)
    val bitcoinjSignature : ECDSASignature = bitcoinjKey.sign(Sha256Hash.ZERO_HASH)
    signature.hex must be (BitcoinSUtil.encodeHex(bitcoinjSignature.encodeToDER()))

  }

  it must "sign a hex string" in {
    val key = ECPrivateKey.freshPrivateKey
    val hash = DoubleSha256Digest("180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19")
    val signature = key.sign(hash)
    key.publicKey.verify("180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19", signature) must be (true)
  }

  it must "sign the hex string with an explicitly given private key" in {
    val key1 = ECPrivateKey.freshPrivateKey
    val key2 = ECPrivateKey.freshPrivateKey
    val hash = DoubleSha256Digest("180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19")
    val signature = key1.sign(hash,key2)
    key2.publicKey.verify(hash, signature) must be (true)
  }

  it must "create a DER encoded signature" in {
    val key = ECPrivateKey.freshPrivateKey
    val hash = DoubleSha256Digest("180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19")
    val signature = key.sign(hash)
    signature.isDEREncoded must be (true)
  }

}
