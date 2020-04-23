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
import applet.SecureChannelManagerBase;
import emcardtools.CardManager;
import javacard.framework.SystemException;
import jpake.jpakeActiveActor;
import jpake.jpakeKeyAgreementException;
import jpake.jpakePassivePayload;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class SecureChannelManagerOnComputer extends SecureChannelManagerBase {
    private static final byte[] jPakeUserId = "COMPUTER".getBytes();

    private final jpakeActiveActor jpakeActiveActor;
    private final CardManager cardManager;

    public SecureChannelManagerOnComputer(byte[] pin, CardManager cardManager) {
        super();
        // TODO: hash pin?
        jpakeActiveActor = new jpakeActiveActor(jPakeUserId, pin);
        this.cardManager = cardManager;
    }

    public void performKeyAgreement() throws CardException, EmeraldProtocolException {
        if (isSecureChannelEstablished()) {
            // TODO count incorrect counter and consider blocking the application
            // key agreement for this session already happened
            throw new EmeraldProtocolException(new EmIllegalStateException());
        }

        ResponseAPDU response;
        byte[] afpb = jpakeActiveActor.prepareFirstPayload().toBytes();
        response = cardManager.transmit(
            new CommandAPDU(CLA_KEY_AGREEMENT, INS_KEY_AGREEMENT_PC2SC_1, 0x00, 0x00,
                afpb)
        );
        if(response == null || response.getSW() != 0x9000){
            throw new EmeraldProtocolException();
        };

        final byte[] ppb = response.getData();
        try {
            jpakeActiveActor.verifyIncoming(jpakePassivePayload.fromBytes(ppb));
        } catch (jpakeKeyAgreementException
            | EmIllegalArgumentException
            | IllegalArgumentException
            | ArrayIndexOutOfBoundsException
            | NullPointerException
            | SystemException e) {
            throw new EmeraldProtocolException(e);
        }

        byte[] aspb = jpakeActiveActor.prepareSecondPayload().toBytes();
        response = cardManager.transmit(
            new CommandAPDU(CLA_KEY_AGREEMENT, INS_KEY_AGREEMENT_PC2SC_2, 0x00, 0x00,
                aspb)
        );
        if(response == null || response.getSW() != 0x9000){
            throw new EmeraldProtocolException();
        };

        setKey(jpakeActiveActor.derivePlainCommonKey());
    }

    @Override
    public void clearSessionData() {
        super.clearSessionData();
        // TODO jpakeActiveActor.clearSessionData()
    }
}
