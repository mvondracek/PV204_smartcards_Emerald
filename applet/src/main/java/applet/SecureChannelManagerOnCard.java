/*
Team Emerald (in alphabetical order):
@OTristanF https://github.com/OTristanF
@lsolodkova https://github.com/lsolodkova
@mvondracek https://github.com/mvondracek
 */

package applet;

import static applet.EmeraldProtocol.CLA_KEY_AGREEMENT;
import static applet.EmeraldProtocol.INS_KEY_AGREEMENT_PC2SC_1;
import static applet.EmeraldProtocol.INS_KEY_AGREEMENT_PC2SC_2;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.SystemException;
import javacard.framework.Util;
import jpake.jpakeActiveFirstPayload;
import jpake.jpakeActiveSecondPayload;
import jpake.jpakeKeyAgreementException;
import jpake.jpakePassiveActor;

import java.util.Arrays;

public class SecureChannelManagerOnCard extends SecureChannelManagerBase {
    private static final byte[] jPakeUserId = "CARD".getBytes();

    private final jpakePassiveActor jpakePassiveActor;

    public SecureChannelManagerOnCard(byte[] pin) {
        super();
        // TODO: hash pin?
        jpakePassiveActor = new jpakePassiveActor(jPakeUserId, pin);
    }


    public void processKeyAgreement(APDU apdu) throws EmeraldProtocolException {
        if (isSecureChannelEstablished()) {
            // count incorrect counter and consider blocking the card
            // key agreement for this session already happened
            throw new EmeraldProtocolException(new EmIllegalStateException());
        }

        byte[] apduBuffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        final short offsetCommandData = apdu.getOffsetCdata();

        if (apduBuffer[ISO7816.OFFSET_CLA] != CLA_KEY_AGREEMENT) {
            // we expect only APDUs from key agreement part
            // count incorrect counter and consider blocking the card
            throw new EmeraldProtocolException();
        }

        switch (apduBuffer[ISO7816.OFFSET_INS]) {
            case INS_KEY_AGREEMENT_PC2SC_1: {
                byte[] afpb = Arrays.copyOfRange(apduBuffer, offsetCommandData,
                    offsetCommandData + dataLen);

                try {
                    jpakeActiveFirstPayload afp = jpakeActiveFirstPayload.fromBytes(afpb);
                    jpakePassiveActor.verifyFirstIncoming(afp);
                } catch (EmIllegalArgumentException
                    | IllegalArgumentException
                    | ArrayIndexOutOfBoundsException
                    | NullPointerException
                    | SystemException
                    | jpakeKeyAgreementException e) {
                    // invalid value of J-PAKE active first payload
                    // count incorrect counter and consider blocking the card
                    throw new EmeraldProtocolException(e);
                }
                // send reply
                byte[] pasivePayloadBytes = jpakePassiveActor.preparePassivePayload().toBytes();
                Util.arrayCopyNonAtomic(pasivePayloadBytes, (short) 0,
                    apduBuffer, offsetCommandData, (short) pasivePayloadBytes.length);
                apdu.setOutgoingAndSend(offsetCommandData, (short) pasivePayloadBytes.length);
                break;
            }
            case INS_KEY_AGREEMENT_PC2SC_2: {
                byte[] aspb = Arrays.copyOfRange(apduBuffer, offsetCommandData,
                    offsetCommandData + dataLen);

                try {
                    jpakeActiveSecondPayload asp = jpakeActiveSecondPayload.fromBytes(aspb);
                    jpakePassiveActor.verifySecondIncoming(asp);
                } catch (EmIllegalArgumentException
                    | IllegalArgumentException
                    | ArrayIndexOutOfBoundsException
                    | NullPointerException
                    | SystemException
                    | jpakeKeyAgreementException e) {
                    // invalid value of J-PAKE active second payload
                    // count incorrect counter and consider blocking the card
                    throw new EmeraldProtocolException(e);
                }

                setKey(jpakePassiveActor.derivePlainCommonKey());
                // empty response
                apdu.setOutgoingAndSend(offsetCommandData, (short) 0);
                break;
            }
            default:
                // incorrect key agreement instruction
                // attacker is trying to communicate with incorrect key agreement protocol
                // count incorrect counter and consider blocking the card
                throw new EmeraldProtocolException();
                // break; // unreachable
        }
    }

    @Override
    public void clearSessionData() {
        super.clearSessionData();
        jpakePassiveActor.clearSessionData();
    }
}
