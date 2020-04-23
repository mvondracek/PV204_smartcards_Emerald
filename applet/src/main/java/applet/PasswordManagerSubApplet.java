/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import static applet.EmeraldProtocol.MESSAGE_GET_PASSWORD;
import static applet.EmeraldProtocol.MESSAGE_OK_GET;
import static applet.EmeraldProtocol.MESSAGE_OK_SET;
import static applet.EmeraldProtocol.MESSAGE_SET_PASSWORD;
import static applet.EmeraldProtocol.MESSAGE_TYPE_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_LENGTH_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_SLOTS_COUNT;
import static applet.EmeraldProtocol.PASSWORD_SLOT_ID_OFFSET;
import static applet.EmeraldProtocol.PASSWORD_SLOT_LENGTH;
import static applet.EmeraldProtocol.PASSWORD_VALUE_OFFSET;

/**
 * Example functionality of the applet - Password Manager.
 * Can store up to {@link EmeraldProtocol#PASSWORD_SLOTS_COUNT} passwords set by user over secure
 * channel.
 */
public class PasswordManagerSubApplet {
    // persistent storage for the password manager
    /**
     * Slots for storing user's passwords.
     *
     * <p>Array of length {@link EmeraldProtocol#PASSWORD_SLOTS_COUNT}.
     */
    private final PasswordSlot[] userPasswordSlots;

    public PasswordManagerSubApplet() {
        userPasswordSlots = new PasswordSlot[PASSWORD_SLOTS_COUNT];
        for (short slotId = 0; slotId < PASSWORD_SLOTS_COUNT; slotId++) {
            userPasswordSlots[slotId] = new PasswordSlot(PASSWORD_SLOT_LENGTH);
        }
    }

    public byte[] process(byte[] message) throws EmeraldProtocolException {
        byte slotId = message[PASSWORD_SLOT_ID_OFFSET];

        if (!(0 <= slotId && slotId < PASSWORD_SLOTS_COUNT)) {
            // incorrect password slot
            // attacker is trying to communicate with incorrect PIN
            // count incorrect counter and consider blocking the card
            throw new EmeraldProtocolException();
        }

        byte[] responsePlaintext = new byte[32];
        switch (message[MESSAGE_TYPE_OFFSET]) {
            case MESSAGE_SET_PASSWORD: {
                if (message[PASSWORD_LENGTH_OFFSET] < 0
                    || message[PASSWORD_LENGTH_OFFSET] > PASSWORD_SLOT_LENGTH) {
                    // invalid password length
                    // attacker is trying to communicate with incorrect PIN
                    // count incorrect counter and consider blocking the card
                    throw new EmeraldProtocolException();
                }
                // set password to selected slot
                userPasswordSlots[slotId].setPassword(message, PASSWORD_VALUE_OFFSET,
                    message[PASSWORD_LENGTH_OFFSET]);

                // prepare response
                responsePlaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_OK_SET;
                break;
            }
            case MESSAGE_GET_PASSWORD: {
                // prepare response
                responsePlaintext[MESSAGE_TYPE_OFFSET] = MESSAGE_OK_GET;
                responsePlaintext[PASSWORD_SLOT_ID_OFFSET] = message[PASSWORD_SLOT_ID_OFFSET];
                responsePlaintext[PASSWORD_LENGTH_OFFSET] = userPasswordSlots[slotId].getPasswordLength();

                // get password from selected slot
                userPasswordSlots[slotId].getPassword(responsePlaintext, PASSWORD_VALUE_OFFSET);
                break;
            }
            default:
                // incorrect message
                // attacker is trying to communicate with incorrect PIN
                // count incorrect counter and consider blocking the card
                throw new EmeraldProtocolException();
        }
        return responsePlaintext;
    }
}
