using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace LibConeshell.Test;

[TestClass]
public class ConeshellV2Tests
{
    [TestMethod]
    public void ConeshellV2_GameServer_ParsesMessage()
    {
        var serverPrivKey = new X25519PrivateKeyParameters(Convert.FromHexString("2021883C819DB7E84496E9B5AEC6956C1ED7E442C7B0A2503C001EC8886CE94B"));
        //var serverPubKey = new X25519PublicKeyParameters(Convert.FromHexString("50BFB7EBD0482B85A124736BCA54789746CEA4FFB74604FA15AF299C979C2103"));
        var coneshell = new ConeshellV2(new byte[16]);

        var encryptedMessage =
            Convert.FromHexString(
                "c0de0002897be23fdd8c3860e4b483339133194c5b01e34258ab799ba3eef3940139c15c4b36d0c15946492913982e940ca7d16ccb782a92ae");
        var expectedMesage = new byte[] {0x80};
        var (actualMessage, secret) = coneshell.DecryptRequestMessage(encryptedMessage, serverPrivKey);

        CollectionAssert.AreEqual(expectedMesage, actualMessage,
            "Server did not decrypt official client message properly.");
    }

    [TestMethod]
    public void ConeshellV2_GameServer_ParsesMessageCompressed()
    {
        var serverPrivKey = new X25519PrivateKeyParameters(Convert.FromHexString("2021883C819DB7E84496E9B5AEC6956C1ED7E442C7B0A2503C001EC8886CE94B"));
        var coneshell = new ConeshellV2(new byte[16]);

        var encryptedMessage =
            Convert.FromHexString(
                "c0de0002ba7441a419bc010c745c79362278860fc90306e49787b27dbb56fa62b921df061c113691b7e733adc380afecd8e78b9212a1ff05c07cebdc771d2962bdd1f597b04b82033266954660f9b4f44224533169");
        var expectedMesage = Encoding.UTF8.GetBytes("aaaabbbbaaaaccccddddeeeeaaaa");

        var (actualMessage, secret) = coneshell.DecryptRequestMessage(encryptedMessage, serverPrivKey);

        CollectionAssert.AreEqual(expectedMesage, actualMessage,
            "Server did not decrypt compressed official client message properly.");
    }

    [TestMethod]
    public void ConeshellV2_GameClient_EncryptsMessage()
    {
        var clientPrivateKey = new X25519PrivateKeyParameters(
            Convert.FromHexString("1026cee8b3d3ba76f9db37a5df2a167edd33b6fada74b040e654e55ff40ac846"));

        var serverPublicKey =
            new X25519PublicKeyParameters(
                Convert.FromHexString("d733a12a53e53153b1ffd8908d28e0e1be2f03b17d9d47deca8285070094d849"));

        var coneshell = new ConeshellV2(MD5.HashData(Encoding.UTF8.GetBytes("fd1d8aa8adfa3a5b")), serverPublicKey);

        var expectedEncryptedMessage =
            Convert.FromHexString(
                "c0de000201c5b2d982fc599326159d2fa4697c95202bc3c264db33870a54bf38312ad20b4f1a1a98779e3cbdc5085707fc49abf10ba8c7e84f");
        var message = new byte[] {0x80};

        var (actualEncryptedMessage, secret) = coneshell.EncryptRequestMessage(message, clientPrivateKey);

        CollectionAssert.AreEqual(expectedEncryptedMessage, actualEncryptedMessage,
            "Server encrypted request did not match official encrypted client message properly.");
    }

    [TestMethod]
    public void ConeshellV2_ClientServer_ParsesMessage()
    {
        var serverKeypair = Coneshell.GenerateKeyPair();
        var serverPrivKey = (X25519PrivateKeyParameters) serverKeypair.Private;
        var serverPubKey = (X25519PublicKeyParameters) serverKeypair.Public;

        var testMessage = Encoding.UTF8.GetBytes("ConeshellTestMessage");
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var coneshell = new ConeshellV2(deviceUdid, serverPubKey);

        var (clientEncrypted, clientSecret) = coneshell.EncryptRequestMessage(testMessage);
        var (serverDecrypted, serverSecret) = coneshell.DecryptRequestMessage(clientEncrypted, serverPrivKey);

        CollectionAssert.AreEqual(clientSecret, serverSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testMessage, serverDecrypted, "Server did not decrypt client message properly.");
    }

    [TestMethod]
    public void ConeshellV2_ServerClient_ParsesMessage()
    {
        var secret = RandomNumberGenerator.GetBytes(32);

        var testMessage = Encoding.UTF8.GetBytes("ConeshellTestMessage");
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var coneshell = new ConeshellV2(deviceUdid);

        var encrypted = coneshell.EncryptResponseMessage(testMessage, secret);
        var decrypted = coneshell.DecryptResponseMessage(encrypted, secret);

        CollectionAssert.AreEqual(testMessage, decrypted, "Client did not decrypt server message properly.");
    }

    [TestMethod]
    public void ConeshellV2_ClientServer_ParsesMessageCompressed()
    {
        var serverKeypair = Coneshell.GenerateKeyPair();
        var serverPrivKey = (X25519PrivateKeyParameters)serverKeypair.Private;
        var serverPubKey = (X25519PublicKeyParameters)serverKeypair.Public;

        var testMessage = Encoding.UTF8.GetBytes("ConeshellTestMessage");
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var coneshell = new ConeshellV2(deviceUdid, serverPubKey);

        var (clientEncrypted, clientSecret) = coneshell.EncryptRequestMessage(testMessage, shouldCompress: true);
        var (serverDecrypted, serverSecret) = coneshell.DecryptRequestMessage(clientEncrypted, serverPrivKey);

        CollectionAssert.AreEqual(clientSecret, serverSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testMessage, serverDecrypted, "Server did not decrypt client message properly.");
    }

    [TestMethod]
    public void ConeshellV2_ServerClient_ParsesMessageCompressed()
    {
        var secret = RandomNumberGenerator.GetBytes(32);

        var testMessage = Encoding.UTF8.GetBytes("ConeshellTestMessage");
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var coneshell = new ConeshellV2(deviceUdid);

        var encrypted = coneshell.EncryptResponseMessage(testMessage, secret, true);
        var decrypted = coneshell.DecryptResponseMessage(encrypted, secret);

        CollectionAssert.AreEqual(testMessage, decrypted, "Client did not decrypt server message properly.");
    }
}