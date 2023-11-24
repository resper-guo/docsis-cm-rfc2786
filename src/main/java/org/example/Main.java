
package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.security.SecurityProtocols.SecurityProtocolType;
import org.snmp4j.security.dh.DHOperations;
import org.snmp4j.security.dh.DHParameters;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {

    // rfc2409 6.2
    public static final BigInteger P2 = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
            "FFFFFFFFFFFFFFFF",
            16);

    public static final BigInteger G = new BigInteger("2");

    public static final DHParameters DEFAULT_DHParameters = new DHParameters(P2, G, 16);

    public static void main(String[] args) throws Exception {

        //LogFactory.setLogFactory(new ConsoleLogFactory());
        //ConsoleLogAdapter.setDebugEnabled(true);

        Security.addProvider(new BouncyCastleProvider());

        KeyPair keyPairA = DHOperations.generatePublicKey(DEFAULT_DHParameters);

        //System.out.println("Public Key Info:");
        //System.out.format("%s\n\n", keyPairA.getPublic().toString());

        // ===================================================================================================================
        System.out.print("\nPlease copy the Public Number 'y' into CM configuration file TLV34.2\n");
        System.out.print("y: ");
        byte[] y = DHOperations.keyToBytes(keyPairA.getPublic());
        for (byte b : y)
        {
            System.out.format("%02X", b);
        }
        System.out.print("\n\nUpload the file into TFTP server.\n");
        System.out.print("\nMake CM online again.\n");
        System.out.print("\nThen press any key to continue: ");
        System.in.readNBytes(1);
        // ===================================================================================================================

        Address targetAddress = GenericAddress.parse("udp:10.10.120.53/161");

        TransportMapping<? extends Address> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);

        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
        SecurityModels.getInstance().addSecurityModel(usm);

        OctetString securityName = new OctetString(DHOperations.DH_KICKSTART_SEC_NAME);
        snmp.getUSM().addUser(securityName, new UsmUser(securityName, AuthMD5.ID, null, PrivDES.ID, null));

        UserTarget target = new UserTarget();
        target.setAddress(targetAddress);
        target.setVersion(SnmpConstants.version3);
        target.setRetries(3);
        target.setTimeout(3000);

        transport.listen();

        System.out.print("\nDHKickstartPublicKeys: \n");
        DefaultPDUFactory pduFactory = new DefaultPDUFactory();
        HashSet<OctetString> managerPublic = new HashSet<OctetString>();
        managerPublic.add(new OctetString(DHOperations.keyToBytes(keyPairA.getPublic())));
        Map<OctetString, OctetString[]>  pubKeyMap = DHOperations.getDHKickstartPublicKeys(snmp, pduFactory, target, managerPublic);

        if (pubKeyMap.isEmpty())
        {
            System.out.print("\nCan not get DHKickstartPublicKeys.\n");
            return;
        }

        for (OctetString key : pubKeyMap.keySet())
        {
            OctetString[] vales = pubKeyMap.get(key);

            System.out.format("\nusmDHKickstartMgrPublic    : %s", key.toString());
            System.out.format("\nusmDHKickstartMyPublic     : %s", vales[0].toString());
            System.out.format("\nusmDHKickstartSecurityName : %s", vales[1].toString());

            KeyAgreement keyAgreementA = DHOperations.getInitializedKeyAgreement(keyPairA);
            byte[] sharedKeyA = DHOperations.computeSharedKey(keyAgreementA, vales[0].toByteArray(), DEFAULT_DHParameters);
            byte[] keyAuth = deriveKeyPBKDF2(sharedKeyA, 16, SecurityProtocolType.authentication);
            byte[] keyPriv= deriveKeyPBKDF2(sharedKeyA, 16, SecurityProtocolType.privacy);

            System.out.print("\nsharedKey : ");
            for (byte b : sharedKeyA)
            {
                System.out.format("%02X", b);
            }

            System.out.print("\nkeyAuth : ");
            for (byte b : keyAuth)
            {
                System.out.format("%02X", b);
            }

            System.out.print("\nkeyPriv : ");
            for (byte b : keyPriv)
            {
                System.out.format("%02X", b);
            }

            System.out.print("\nTry to get sysDescr: ");
            SNMPv3Get_sysDescr(targetAddress, new OctetString("docsisManager"), keyAuth, keyPriv);
        }
        System.out.print("\n");
    }
    private static void SNMPv3Get_sysDescr(Address targetAddress, OctetString securityName, byte[] authKey, byte[] privKey) throws Exception
    {
        Snmp snmp= new Snmp(new DefaultUdpTransportMapping());
        snmp.listen();

        SecurityProtocols securityProtocols = SecurityProtocols.getInstance();
        byte[] myEngineID = MPv3.createLocalEngineID();
        USM usm = new USM(securityProtocols, new OctetString(myEngineID), 0);
        usm.setEngineDiscoveryEnabled(true);
        SecurityModels.getInstance().addSecurityModel(usm);

        securityProtocols.addAuthenticationProtocol(new AuthMD5());
        securityProtocols.addPrivacyProtocol(new PrivDES());

        byte[] targetEngineID = snmp.discoverAuthoritativeEngineID(targetAddress, 1000);
        snmp.getUSM().addLocalizedUser(targetEngineID, securityName, AuthMD5.ID, authKey, PrivDES.ID, privKey);

        UserTarget target=new UserTarget();
        target.setVersion(SnmpConstants.version3);
        target.setAuthoritativeEngineID(targetEngineID);
        target.setAddress(targetAddress);
        target.setSecurityModel(SecurityModel.SECURITY_MODEL_USM);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(securityName);
        target.setTimeout(3000);
        target.setRetries(0);

        ScopedPDU pdu=new ScopedPDU();
        pdu.add(new VariableBinding(new OID(".1.3.6.1.2.1.1.1.0")));
        pdu.setType(PDU.GET);

        ResponseEvent responseEvent = snmp.send(pdu, target);
        System.out.println("Synchronize message from "
                + responseEvent.getPeerAddress() + "\r\n"+"request:"
                + responseEvent.getRequest() + "\r\n"+"response:"
                + responseEvent.getResponse());

        List<? extends VariableBinding> vbs = responseEvent.getResponse().getVariableBindings();
        System.out.print("\nVariableBinding: \n");
        for(VariableBinding vb : vbs)
        {
            System.out.format("%s: %s", vb.getOid().toDottedString(), vb.toValueString());
        }
    }

    public static byte[] deriveKeyPBKDF2(byte[] shareKey, int keyLength,
                                         SecurityProtocols.SecurityProtocolType securityProtocolType) {
        final OctetString PBKDF2_AUTH_SALT = OctetString.fromHexStringPairs("98dfb5ac");
        final OctetString PBKDF2_PRIV_SALT = OctetString.fromHexStringPairs("d1310ba6");

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1And8bit", "BC");
            byte[] salt = (securityProtocolType == SecurityProtocols.SecurityProtocolType.authentication) ?
                    PBKDF2_AUTH_SALT.getValue() : PBKDF2_PRIV_SALT.getValue();
            char[] keyCharArray = new char[shareKey.length];
            for(int i = 0; i < shareKey.length; i++)
            {
                keyCharArray[i] = (char)shareKey[i];
            }
            PBEKeySpec spec = new PBEKeySpec(keyCharArray, salt, 500, keyLength*8);
            return skf.generateSecret(spec).getEncoded();
        }
        catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
