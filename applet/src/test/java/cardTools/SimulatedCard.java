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

package cardTools;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

/**
 *
 * @author Petr Svenda
 */
public class SimulatedCard extends Card {

    @Override
    public ATR getATR() {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public String getProtocol() {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public CardChannel getBasicChannel() {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public CardChannel openLogicalChannel() throws CardException {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public void beginExclusive() throws CardException {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public void endExclusive() throws CardException {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public byte[] transmitControlCommand(int i, byte[] bytes) throws CardException {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public void disconnect(boolean bln) throws CardException {
        // do nothing
    }
}
