using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;

namespace LibConeshell.Test;

[TestClass]
public class ConeshellV3Tests
{

    /*[TestMethod]
    public void ConeshellV3_GameClient_EncryptsMessage()
    {
        var clientPrivateKey = new X25519PrivateKeyParameters(
            Convert.FromHexString("1026cee8b3d3ba76f9db37a5df2a167edd33b6fada74b040e654e55ff40ac846"));

        var serverPublicKey =
            new X25519PublicKeyParameters(
                Convert.FromHexString("d733a12a53e53153b1ffd8908d28e0e1be2f03b17d9d47deca8285070094d849"));

        var coneshell = new ConeshellV3(deviceId, versionKey, serverPublicKey);

        var expectedEncryptedMessage =
            Convert.FromHexString(
                "c0de000201c5b2d982fc599326159d2fa4697c95202bc3c264db33870a54bf38312ad20b4f1a1a98779e3cbdc5085707fc49abf10ba8c7e84f");
        var message = new byte[] { 0x80 };

        var (actualEncryptedMessage, secret) = coneshell.EncryptRequestMessage(message, clientPrivateKey);

        CollectionAssert.AreEqual(expectedEncryptedMessage, actualEncryptedMessage,
            "Server encrypted request did not match official encrypted client message properly.");
    }*/

    [TestMethod]
    public void ConeshellV3_ClientServer_ParsesMessage()
    {
        var serverKeypair = Coneshell.GenerateKeyPair();
        var serverPrivKey = (X25519PrivateKeyParameters)serverKeypair.Private;
        var serverPubKey = (X25519PublicKeyParameters)serverKeypair.Public;

        var testMessage = Encoding.UTF8.GetBytes("ConeshellTestMessage");
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey, serverPubKey);

        var (clientEncrypted, clientSecret) = coneshell.EncryptRequestMessage(testMessage);
        var (serverDecrypted, serverSecret) =
            coneshell.DecryptRequestMessage(clientEncrypted, serverPrivKey);

        CollectionAssert.AreEqual(clientSecret, serverSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testMessage, serverDecrypted, "Server did not decrypt client message properly.");
    }

    [TestMethod]
    public void ConeshellV3_ServerClient_ParsesMessage()
    {
        var secret = RandomNumberGenerator.GetBytes(32);

        var testMessage = Encoding.UTF8.GetBytes("ConeshellTestMessage");
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey);

        var encrypted = coneshell.EncryptResponseMessage(testMessage, secret);
        var decrypted = coneshell.DecryptResponseMessage(encrypted, secret);

        CollectionAssert.AreEqual(testMessage, decrypted, "Client did not decrypt server message properly.");
    }

    [TestMethod]
    public void ConeshellV3_ClientServer_ParsesMessageCompressed()
    {
        var serverKeypair = Coneshell.GenerateKeyPair();
        var serverPrivKey = (X25519PrivateKeyParameters)serverKeypair.Private;
        var serverPubKey = (X25519PublicKeyParameters)serverKeypair.Public;

        var testMessage = Encoding.UTF8.GetBytes("ConeshellTestMessage");
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey, serverPubKey);

        var (clientEncrypted, clientSecret) = coneshell.EncryptRequestMessage(testMessage, shouldCompress: true);
        var (serverDecrypted, serverSecret) =
            coneshell.DecryptRequestMessage(clientEncrypted, serverPrivKey);

        CollectionAssert.AreEqual(clientSecret, serverSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testMessage, serverDecrypted, "Server did not decrypt client message properly.");
    }

    [TestMethod]
    public void ConeshellV3_ServerClient_ParsesMessageCompressed()
    {
        var secret = RandomNumberGenerator.GetBytes(32);

        var testMessage = Encoding.UTF8.GetBytes("ConeshellTestMessage");
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey);

        var encrypted = coneshell.EncryptResponseMessage(testMessage, secret, true);
        var decrypted = coneshell.DecryptResponseMessage(encrypted, secret);

        CollectionAssert.AreEqual(testMessage, decrypted, "Client did not decrypt server message properly.");
    }
}