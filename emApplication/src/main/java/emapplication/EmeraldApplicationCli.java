/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package emapplication;


import applet.EmeraldApplet;
import applet.EmeraldProtocol;
import static applet.EmeraldProtocol.CLA_ENCRYPTED;
import static applet.EmeraldProtocol.MESSAGE_GET_PASSWORD;
import static applet.EmeraldProtocol.MESSAGE_LENGTH;
import static applet.EmeraldProtocol.MESSAGE_OK_GET;
import static applet.EmeraldProtocol.MESSAGE_OK_SET;
import static applet.EmeraldProtocol.MESSAGE_SET_PASSWORD;
import static applet.EmeraldProtocol.MESSAGE_TYPE_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_LENGTH_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_SLOT_ID_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_VALUE_OFFSET;
import static applet.EmeraldProtocol.PIN_LENGTH;
import applet.EmeraldProtocolException;
import applet.SecureChannelManagerOnComputer;
import emcardtools.CardManager;
import emcardtools.RunConfig;
import emcardtools.Util;
import static emcardtools.Util.prepareParameterData;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;
import java.util.Scanner;

public class EmeraldApplicationCli {
    public static final String AID = "0102030405060708090102";
    public static final byte[] AID_BYTES = Util.hexStringToByteArray(AID);
    public static final String UI_ERROR_IN_COMMUNICATION = "Error: Error in communication with the card.";
    public static final String UI_DETAILED_INFO_ABOUT_ERROR = "Detailed info about this error:";
    final CardManager cardManager;
    SecureChannelManagerOnComputer secureChannelManagerOnComputer;


    public EmeraldApplicationCli() {
        cardManager = new CardManager(true, AID_BYTES);
    }

    public static void main(String[] args) {
        final EmeraldApplicationCli cli = new EmeraldApplicationCli();
        cli.run();
        System.out.println("exit");
    }

    public void run() {
        printBanner();
        // connect to the card
        try {
            connect(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
        } catch (Exception e) {
            System.err.println("Error: Could not connect to the card.");
            System.err.println("Detailed info about this error:");
            e.printStackTrace();
            return;
        }
        System.out.println("PC ... SC: Established connection to smartcard.");

        // ask user to enter PIN to command line
        byte[] pin = requirePinInput();
        System.out.println(String.format("PC       : Using PIN `%s`", Arrays.toString(pin)));

        secureChannelManagerOnComputer = new SecureChannelManagerOnComputer(pin, cardManager);

        try {
            demoPlaintext();

            System.out.println("PC <-> SC: Key agreement started.");
            secureChannelManagerOnComputer.performKeyAgreement();
            System.out.println("PC       : New shared session key established.");
            System.out.println("PC <-> SC: Key agreement finished successfully.");

            erasePin(pin); pin = null;

            demoPasswordStorage();

        } catch (CardException e) {
            System.err.println(UI_ERROR_IN_COMMUNICATION);
            System.err.println(UI_DETAILED_INFO_ABOUT_ERROR);
            e.printStackTrace();
            secureChannelManagerOnComputer.clearSessionData();
            return;
        } catch (EmProtocolError | EmeraldProtocolException e) {
            System.err.println(UI_ERROR_IN_COMMUNICATION);
            System.err.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            System.err.println("@ \"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\" @");
            System.err.println("@     PIN IS INCORRECT OR THIS SMARTCARD IS MALICIOUS     @");
            System.err.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            System.err.println(UI_DETAILED_INFO_ABOUT_ERROR);
            e.printStackTrace();
            secureChannelManagerOnComputer.clearSessionData();
            return;
        }

        System.out.println("Done.");
    }

    /**
     * Overwrite pin so it's not stored in RAM.
     * @param pin byte array with pin of length {@link EmeraldProtocol#PIN_LENGTH}
     */
    private void erasePin(byte[] pin) {
        for (int i = 0; i < PIN_LENGTH; i++) {
            pin[i] = (byte) 0xFF;
        }
    }

    private byte[] requirePinInput() {
        byte[] pin = new byte[PIN_LENGTH];
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("PC       : Enter 4 digit PIN.");
            // TODO: SECURITY: Use some mutable type for `pinInput` and wipe this object in RAM
            //  after this method finishes to protect subsequent memory dump.
            String pinInput = scanner.next();
            if (pinInput.length() != PIN_LENGTH) {
                System.out.println("PC       : PIN length must be 4.");
                continue;
            }

            // check if input pin contains only digits
            if (!(Character.isDigit(pinInput.charAt(0))
                && Character.isDigit(pinInput.charAt(1))
                && Character.isDigit(pinInput.charAt(2))
                && Character.isDigit(pinInput.charAt(3))
            )) {
                System.out.println("PC       : PIN must be 4 digits.");
                continue;
            }

            // pin has valid format
            for (int i = 0; i < PIN_LENGTH; i++) {
                pin[i] = (byte) (pinInput.charAt(i) - '0');
            }
            break;
        }
        return pin;
    }

    void connect(RunConfig.CARD_TYPE cardType) throws Exception {
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

            System.out.println("PC       : Selected communication with EmeraldApplet in a simulator.");
            System.out.println(
                String.format("PC       : Simulated applet was installed with PIN `%d %d %d %d`.",
                    simulatedPin[0], simulatedPin[1], simulatedPin[2], simulatedPin[3]));

        }

        if (!cardManager.Connect(runConfig)) {
            throw new RuntimeException("Connection failed");
        }
    }

    public void setPassword(byte passwordSlotId, String password)
        throws CardException, EmProtocolError, EmeraldProtocolException {
        System.out.println(String.format("PC --> SC: Set password `%s` to slot %d.",
            password, passwordSlotId));

        byte[] passwordBytes = password.getBytes();
        byte[] plaintext = new byte[MESSAGE_LENGTH];
        plaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_SET_PASSWORD;
        plaintext[PASSWORD_SLOT_ID_OFFSET] = passwordSlotId;
        plaintext[PASSWORD_LENGTH_OFFSET] = (byte) passwordBytes.length;
        System.arraycopy(passwordBytes, 0, plaintext, PASSWORD_VALUE_OFFSET,
            passwordBytes.length);

        byte[] ciphertext = secureChannelManagerOnComputer.encrypt(plaintext);
        CommandAPDU command = new CommandAPDU(CLA_ENCRYPTED, 0x00, 0x00, 0x00, ciphertext);

        ResponseAPDU response = cardManager.transmit(command);
        checkApduResponseStatus(response);

        byte[] responsePlaintext = secureChannelManagerOnComputer.decrypt(response.getData(),
            (short) 0, (short) response.getData().length);
        // check responsePlaintext
        if (responsePlaintext.length != MESSAGE_LENGTH) {
            throw new EmProtocolError(
                String.format("Incorrect length of plaintext, expected=%d, actual=%d",
                    MESSAGE_LENGTH, responsePlaintext.length));
        }
        if (responsePlaintext[MESSAGE_TYPE_OFFSET] != MESSAGE_OK_SET) {
            throw new EmProtocolError(
                String.format("Unexpected message type, expected=%d (MESSAGE_OK_SET), actual=%d",
                    MESSAGE_OK_SET, responsePlaintext[MESSAGE_TYPE_OFFSET]));
        }

        System.out.println(String.format("PC <== SC: Password successfully set to slot %d.",
            passwordSlotId));
    }

    private void checkApduResponseStatus(ResponseAPDU responseApdu) throws EmProtocolError {
        if (responseApdu == null) {
            throw new EmProtocolError("Missing response.");
        }
        if (responseApdu.getSW() != 0x9000) {
            throw new EmProtocolError(
                String.format("Unexpected response status 0x%04X.", responseApdu.getSW()),
                responseApdu);
        }
    }

    private void checkMessageResponse(byte[] response, byte messageLength, byte messageType,
                                      byte passwordSlotId)
        throws EmProtocolError {
        if (response.length != messageLength) {
            throw new EmProtocolError(
                String.format("Incorrect length of plaintext, expected=%d, actual=%d",
                    messageLength, response.length));
        }
        if (response[MESSAGE_TYPE_OFFSET] != messageType) {
            throw new EmProtocolError(
                String.format("Unexpected message type, expected=%d, actual=%d",
                    messageType, response[MESSAGE_TYPE_OFFSET]));
        }
        if (response[PASSWORD_SLOT_ID_OFFSET] != passwordSlotId) {
            throw new EmProtocolError(
                String.format("Unexpected password slot ID, expected=%d, actual=%d",
                    passwordSlotId, response[PASSWORD_SLOT_ID_OFFSET]));
        }

    }

    public String getPassword(byte passwordSlotId) throws CardException, EmProtocolError, EmeraldProtocolException {
        System.out.println(String.format("PC --> SC: Get password from slot %d.", passwordSlotId));

        byte[] plaintext = new byte[MESSAGE_LENGTH];
        plaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_GET_PASSWORD;
        plaintext[PASSWORD_SLOT_ID_OFFSET] = passwordSlotId;

        byte[] ciphertext = secureChannelManagerOnComputer.encrypt(plaintext);
        CommandAPDU command = new CommandAPDU(CLA_ENCRYPTED, 0x00, 0x00, 0x00, ciphertext);
        ResponseAPDU response = cardManager.transmit(command);

        checkApduResponseStatus(response);

        byte[] responsePlaintext = secureChannelManagerOnComputer.decrypt(response.getData(),
            (short) 0, (short) response.getData().length);

        checkMessageResponse(responsePlaintext, MESSAGE_LENGTH, MESSAGE_OK_GET, passwordSlotId);

        byte[] retrievedPassword = Arrays.copyOfRange(responsePlaintext, PASSWORD_VALUE_OFFSET,
            PASSWORD_VALUE_OFFSET + responsePlaintext[PASSWORD_LENGTH_OFFSET]);

        String retrievedPasswordString = new String(retrievedPassword);

        System.out.println(String.format("PC <== SC: Retrieved password `%s` from slot %d.",
            retrievedPasswordString, passwordSlotId));
        return retrievedPasswordString;
    }

    public void demoPlaintext() throws CardException {
        System.out.println("##################################################");
        System.out.println("Begin: demo plaintext");

        System.out.println("PC --> SC: Sending example plaintext message to card.");
        CommandAPDU command = new CommandAPDU(EmeraldProtocol.CLA_PLAINTEXT, 0x00, 0x00, 0x00);
        ResponseAPDU response;
        response = cardManager.transmit(command);

        System.out.print("PC <== SC: Received response:");
        System.out.println(Arrays.toString(response.getData()));

        System.out.println("End: demo plaintext");
        System.out.println("##################################################");
    }

    public void demoPasswordStorage() throws CardException, EmProtocolError, EmeraldProtocolException {
        System.out.println("##################################################");
        System.out.println("Begin: demo password storage");

        System.out.println();
        setPassword((byte) 0, "All your");
        System.out.println();
        setPassword((byte) 1, "base are");
        System.out.println();
        setPassword((byte) 2, "belong to us");
        System.out.println();
        getPassword((byte) 2);
        System.out.println();
        getPassword((byte) 1);
        System.out.println();
        getPassword((byte) 0);
        System.out.println();

        System.out.println("End: demo password storage");
        System.out.println("##################################################");
    }

    public void printBanner() {
        System.out.print("\n"
            + "    Emerald Password Manager for Smartcards\n"
            + "  __\n"
            + " (`/\\\n"
            + " `=\\/\\ __...--~~~~~-._   _.-~~~~~--...__\n"
            + "  `=\\/\\               \\ /               \\\\\n"
            + "   `=\\/                V                 \\\\\n"
            + "   //_\\___--~~~~~~-._  |  _.-~~~~~~--...__\\\\\n"
            + "  //  ) (..----~~~~._\\ | /_.~~~~----.....__\\\\\n"
            + " ===(     )==========\\\\|//====================\n"
            + "     \\___/           `---`\n\n");
    }

    public class EmProtocolError extends Exception {
        public final ResponseAPDU responseApdu;

        public EmProtocolError(String message, ResponseAPDU responseApdu) {
            super(message);
            this.responseApdu = responseApdu;
        }

        public EmProtocolError(String message) {
            super(message);
            responseApdu = null;
        }
    }
}
