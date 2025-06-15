using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace LibConeshell.Test;

[TestClass]
public class ConeshellV3Tests
{
    [TestMethod]
    public void ConeshellV3_ClientServer_ParsesMessage()
    {
        var serverKeypair = Coneshell.GenerateKeyPair();
        var serverPrivKey = (X25519PrivateKeyParameters)serverKeypair.Private;
        var serverPubKey = (X25519PublicKeyParameters)serverKeypair.Public;

        var testMessage = "ConeshellTestMessage"u8.ToArray();
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey, serverPubKey);

        var (clientEncrypted, clientSecret) = coneshell.EncryptRequestMessage(testMessage);
        var (serverDecrypted, serverSecret) = coneshell.DecryptRequestMessage(clientEncrypted, serverPrivKey);

        CollectionAssert.AreEqual(clientSecret, serverSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testMessage, serverDecrypted, "Server did not decrypt client request properly.");
    }

    [TestMethod]
    public void ConeshellV3_ServerClient_ParsesMessage()
    {
        var secret = RandomNumberGenerator.GetBytes(32);

        var testMessage = "ConeshellTestMessage"u8.ToArray();
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey);

        var encrypted = coneshell.EncryptResponseMessage(testMessage, secret);
        var decrypted = coneshell.DecryptResponseMessage(encrypted, secret);

        CollectionAssert.AreEqual(testMessage, decrypted, "Client did not decrypt server response properly.");
    }

    [TestMethod]
    public void ConeshellV3_ClientServer_ParsesMessageCompressed()
    {
        var serverKeypair = Coneshell.GenerateKeyPair();
        var serverPrivKey = (X25519PrivateKeyParameters)serverKeypair.Private;
        var serverPubKey = (X25519PublicKeyParameters)serverKeypair.Public;

        var testMessage = "ConeshellTestMessage"u8.ToArray();
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey, serverPubKey);

        var (clientEncrypted, clientSecret) = coneshell.EncryptRequestMessage(testMessage, shouldCompress: true);
        var (serverDecrypted, serverSecret) =
            coneshell.DecryptRequestMessage(clientEncrypted, serverPrivKey);

        CollectionAssert.AreEqual(clientSecret, serverSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testMessage, serverDecrypted, "Server did not decrypt compressed client request properly.");
    }

    [TestMethod]
    public void ConeshellV3_ServerClient_ParsesMessageCompressed()
    {
        var secret = RandomNumberGenerator.GetBytes(32);

        var testMessage = "ConeshellTestMessage"u8.ToArray();
        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey);

        var encrypted = coneshell.EncryptResponseMessage(testMessage, secret, true);
        var decrypted = coneshell.DecryptResponseMessage(encrypted, secret);

        CollectionAssert.AreEqual(testMessage, decrypted, "Client did not decrypt compressed server response properly.");
    }

    [TestMethod]
    public void ConeshellV3_Both_RoundtripMessageExchange()
    {
        var serverKeypair = Coneshell.GenerateKeyPair();
        var serverPrivKey = (X25519PrivateKeyParameters)serverKeypair.Private;
        var serverPubKey = (X25519PublicKeyParameters)serverKeypair.Public;

        var testRequest = "ClientTestRequest"u8.ToArray();
        var testResponse = "ServerTestResponse"u8.ToArray();

        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var coneshell = new ConeshellV3(deviceUdid, versionKey, serverPubKey);

        var (encryptedRequest, requestSecretClient) = coneshell.EncryptRequestMessage(testRequest);
        var (decryptedRequest, requestSecretServer) = coneshell.DecryptRequestMessage(encryptedRequest, serverPrivKey);
        var encryptedResponse = coneshell.EncryptResponseMessage(testResponse, requestSecretServer);
        var decryptedResponse = coneshell.DecryptResponseMessage(encryptedResponse, requestSecretServer);

        CollectionAssert.AreEqual(requestSecretClient, requestSecretServer, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testRequest, decryptedRequest, "Server did not decrypt client request properly.");
        CollectionAssert.AreEqual(testResponse, decryptedResponse, "Client did not decrypt server response properly.");
    }
}