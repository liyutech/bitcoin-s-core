package org.bitcoins.core.serializers

import org.bitcoins.core.currency.{CurrencyUnitGenerator, Satoshis}
import org.scalacheck.{Prop, Properties}

/**
  * Created by chris on 6/23/16.
  */
class RawSatoshisSerializerSpec extends Properties("RawSatoshiSerializerSpec") {

  property("Symmetrical serialization") =
    Prop.forAll(CurrencyUnitGenerator.satoshis) { satoshis =>
      Satoshis(satoshis.hex) == satoshis

    }

}