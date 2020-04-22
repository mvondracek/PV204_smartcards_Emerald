/*
This file was merged and modified based on "JavaCard Template project with
Gradle" which was published under MIT license included below.
https://github.com/crocs-muni/javacard-gradle-template-edu

License from 2020-04-18 https://github.com/crocs-muni/javacard-gradle-template-edu/blob/ebcb012a192092678eb9b7f198be5a6a26136f31/LICENSE
~~~
The MIT License (MIT)

Copyright (c) 2015 Dusan Klinec, Martin Paljak, Petr Svenda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
~~~
*/

package emcardtools;

import com.licel.jcardsim.io.JavaxSmartCardInterface;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.nio.ByteBuffer;

/**
 *
 * @author Petr Svenda
 */
public class SimulatedCardChannelLocal extends CardChannel {
    JavaxSmartCardInterface m_simulator;
    SimulatedCard m_card;

    SimulatedCardChannelLocal (JavaxSmartCardInterface simulator) {
        m_simulator = simulator;
        m_card = new SimulatedCard();
    }

    @Override
    public Card getCard() {
        return m_card;
    }

    @Override
    public int getChannelNumber() {
        return 0;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU apdu) throws CardException {
        ResponseAPDU responseAPDU = null;

        try {
            log(apdu);
            responseAPDU = this.m_simulator.transmitCommand(apdu);
            log(responseAPDU);
            // TODO: Add delay corresponding to real cards
            //int delay = OperationTimes.getCardOperationDelay(apdu);
            //Thread.sleep(delay);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return responseAPDU;
    }

    @Override
    public int transmit(ByteBuffer bb, ByteBuffer bb1) throws CardException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void close() throws CardException {
        m_simulator.reset();
    }


    private static void log(CommandAPDU cmd) {
        System.out.printf("--> [%s] %s\n", Util.toHex(cmd.getBytes()), cmd.getBytes().length);
    }

    private static void log(ResponseAPDU response, long time) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("<-- %s %s (%d)\n", Util.toHex(data), swStr,
                    data.length);
        } else {
            System.out.printf("<-- %s\n", swStr);
        }
        if (time > 0) {
            System.out.printf(String.format("Elapsed time %d ms\n", time));
        }
    }

    private static void log(ResponseAPDU response) {
        log(response, 0);
    }
}
