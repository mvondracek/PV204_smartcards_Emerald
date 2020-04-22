/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package emApplication;


import applet.EmeraldApplet;
import applet.EmeraldProtocol;
import applet.SecureChannelManager;
import emCardTools.CardManager;
import emCardTools.RunConfig;
import emCardTools.Util;
import static emCardTools.Util.prepareParameterData;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;

public class EmeraldApplicationCli {
    public static final String AID = "0102030405060708090102";
    public static final byte[] AID_BYTES = Util.hexStringToByteArray(AID);

    final CardManager cardManager;
    final SecureChannelManager secureChannelManager;


    public  EmeraldApplicationCli(){
        cardManager = new CardManager(true, AID_BYTES);
        secureChannelManager = new SecureChannelManager();
    }

    public void run(){
        System.out.println("Emerald Password Manager on Smartcard.");
        try {
            connect(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
        } catch (Exception e) {
            System.err.println("Error: Could not connect to the card.");
            System.err.println("Detailed info about this error:");
            e.printStackTrace();
            return;
        }

        System.err.println("PC->SC: Sending example plaintext message to card.");
        CommandAPDU command = new CommandAPDU(EmeraldProtocol.CLA_PLAINTEXT, 0x00, 0x00, 0x00);
        ResponseAPDU response;
        try {
            response = cardManager.transmit(command);
        } catch (CardException e) {
            System.err.println("Error: Could not communicate with the card.");
            System.err.println("Detailed info about this error:");
            e.printStackTrace();
            return;
        }

        System.err.println("PC<-SC: Received response:");
        System.out.println(Arrays.toString(response.getData()));

        System.out.println("Done.");
    }

    public void connect(RunConfig.CARD_TYPE cardType) throws Exception {
        RunConfig runConfig = RunConfig.getDefaultConfig();
        if (cardType == RunConfig.CARD_TYPE.PHYSICAL) {
            runConfig.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL);
        } else {
            // Running in the simulator.
            // Simulate that there's a card in a reader with our EmeraldApplet which has been
            // already correctly installed. Simulate that this applet has been installed with
            // following PIN.
            byte[] simulatedPin = new byte[]{1, 2, 3, 4};

            byte[] installData = prepareParameterData(AID_BYTES, new byte[0], simulatedPin);
            runConfig.setAppletToSimulate(EmeraldApplet.class)
                .setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL)
                .setbReuploadApplet(true)
                .setInstallData(installData);
        }

        if (!cardManager.Connect(runConfig)) {
            throw new RuntimeException("Connection failed");
        }
    }

    public static void main(String[] args) {
        final EmeraldApplicationCli cli = new EmeraldApplicationCli();
        cli.run();
        System.out.println("exit");
    }
}
