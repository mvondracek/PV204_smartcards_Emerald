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

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import java.util.ArrayList;

import javax.smartcardio.*;
import java.util.List;


/**
 *
 * @author Petr Svenda
 */
public class CardManager {
    protected boolean bDebug = false;
    protected byte[] appletId = null;
    protected Long lastTransmitTime = (long) 0;
    protected CommandAPDU lastCommand = null;
    protected CardChannel channel = null;

    /**
     * Add LC=0 byte to the APDU.
     */
    protected boolean fixLc = true;

    public CardManager(boolean bDebug, byte[] appletAID) {
        this.bDebug = bDebug;
        this.appletId = appletAID;
    }

    /**
     * Card connect
     * @param runCfg run configuration
     * @return true if connected
     * @throws Exception exceptions from underlying connects
     */
    public boolean Connect(RunConfig runCfg) throws Exception {
        boolean bConnected = false;
        switch (runCfg.testCardType) {
            case PHYSICAL: {
                channel = ConnectPhysicalCard(runCfg.targetReaderIndex);
                break;
            }
            case JCOPSIM: {
                channel = ConnectJCOPSimulator(runCfg.targetReaderIndex);
                break;
            }
            case JCARDSIMLOCAL: {
                channel = ConnectJCardSimLocalSimulator(runCfg.appletToSimulate, runCfg.installData);
                break;
            }
            case JCARDSIMREMOTE: {
                channel = null; // Not implemented yet
                break;
            }
            default:
                channel = null;
                bConnected = false;

        }
        if (channel != null) {
            bConnected = true;
        }
        return bConnected;
    }

    public void Disconnect(boolean bReset) throws CardException {
        channel.getCard().disconnect(bReset); // Disconnect from the card
    }

    public CardChannel ConnectPhysicalCard(int targetReaderIndex) throws Exception {
        // JCOP Simulators
        System.out.print("Looking for physical cards... ");
        return connectToCardByTerminalFactory(TerminalFactory.getDefault(), targetReaderIndex);
    }

    public CardChannel ConnectJCOPSimulator(int targetReaderIndex) throws Exception {
        // JCOP Simulators
        System.out.print("Looking for JCOP simulators...");
        int[] ports = new int[]{8050};
        return connectToCardByTerminalFactory(TerminalFactory.getInstance("JcopEmulator", ports), targetReaderIndex);
    }

    private CardChannel ConnectJCardSimLocalSimulator(Class appletClass, byte[] installData) throws Exception {
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        CAD cad = new CAD(System.getProperties());
        JavaxSmartCardInterface simulator = (JavaxSmartCardInterface) cad.getCardInterface();
        if (installData == null) {
            installData = new byte[0];
        }
        AID appletAID = new AID(appletId, (short) 0, (byte) appletId.length);

        AID appletAIDRes = simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        simulator.selectApplet(appletAID);

        return new SimulatedCardChannelLocal(simulator);
    }

    private CardChannel connectToCardByTerminalFactory(TerminalFactory factory, int targetReaderIndex) throws CardException {
        List<CardTerminal> terminals = new ArrayList<>();

        boolean card_found = false;
        CardTerminal terminal = null;
        Card card = null;
        try {
            for (CardTerminal t : factory.terminals().list()) {
                terminals.add(t);
                if (t.isCardPresent()) {
                    card_found = true;
                }
            }
            System.out.println("Success.");
        } catch (Exception e) {
            System.out.println("Failed.");
        }

        if (card_found) {
            System.out.println("Cards found: " + terminals);

            terminal = terminals.get(targetReaderIndex); // Prioritize physical card over simulations

            System.out.print("Connecting...");
            card = terminal.connect("*"); // Connect with the card

            System.out.println(" Done.");

            System.out.print("Establishing channel...");
            channel = card.getBasicChannel();

            System.out.println(" Done.");

            // Select applet (mpcapplet)
            System.out.println("Smartcard: Selecting applet...");

            CommandAPDU cmd = new CommandAPDU(0x00, 0xa4, 0x04, 0x00, appletId);
            ResponseAPDU response = transmit(cmd);
        } else {
            System.out.print("Failed to find physical card.");
        }

        if (card != null) {
            return card.getBasicChannel();
        } else {
            return null;
        }
    }

    public ResponseAPDU transmit(CommandAPDU cmd)
            throws CardException {

        if (isFixLc()){
            cmd = fixApduLc(cmd);
        }

        lastCommand = cmd;
        if (bDebug) {
            log(cmd);
        }

        long elapsed = -System.currentTimeMillis();
        ResponseAPDU response = channel.transmit(cmd);
        elapsed += System.currentTimeMillis();
        lastTransmitTime = elapsed;

        if (bDebug) {
            log(response, lastTransmitTime);
        }

        return response;
    }

    private void log(CommandAPDU cmd) {
        System.out.printf("--> %s\n", Util.toHex(cmd.getBytes()),
                cmd.getBytes().length);
    }

    private void log(ResponseAPDU response, long time) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("<-- %s %s (%d) [%d ms]\n", Util.toHex(data), swStr,
                    data.length, time);
        } else {
            System.out.printf("<-- %s [%d ms]\n", swStr, time);
        }
    }

    private CommandAPDU fixApduLc(CommandAPDU cmd){
        if (cmd.getNc() != 0){
            return cmd;
        }

        byte[] apdu = new byte[] {
                (byte)cmd.getCLA(),
                (byte)cmd.getINS(),
                (byte)cmd.getP1(),
                (byte)cmd.getP2(),
                (byte)0
        };
        return new CommandAPDU(apdu);
    }

    private void log(ResponseAPDU response) {
        log(response, 0);
    }

    private Card waitForCard(CardTerminals terminals)
            throws CardException {
        while (true) {
            for (CardTerminal ct : terminals
                    .list(CardTerminals.State.CARD_INSERTION)) {

                return ct.connect("*");
            }
            terminals.waitForChange();
        }
    }

    public boolean isbDebug() {
        return bDebug;
    }

    public byte[] getAppletId() {
        return appletId;
    }

    public Long getLastTransmitTime() {
        return lastTransmitTime;
    }

    public CommandAPDU getLastCommand() {
        return lastCommand;
    }

    public CardChannel getChannel() {
        return channel;
    }

    public CardManager setbDebug(boolean bDebug) {
        this.bDebug = bDebug;
        return this;
    }

    public CardManager setAppletId(byte[] appletId) {
        this.appletId = appletId;
        return this;
    }

    public CardManager setLastTransmitTime(Long lastTransmitTime) {
        this.lastTransmitTime = lastTransmitTime;
        return this;
    }

    public CardManager setLastCommand(CommandAPDU lastCommand) {
        this.lastCommand = lastCommand;
        return this;
    }

    public CardManager setChannel(CardChannel channel) {
        this.channel = channel;
        return this;
    }

    public boolean isFixLc() {
        return fixLc;
    }

    public CardManager setFixLc(boolean fixLc) {
        this.fixLc = fixLc;
        return this;
    }
}
