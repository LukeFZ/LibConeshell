using System.Diagnostics;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace LibConeshell.Test;

[TestClass]
public class ConeshellV4Tests
{
    public static void GetRandomConeshell(out ConeshellV4 instance, out X25519PrivateKeyParameters serverPrivateKey, bool addAuthData = false)
    {
        var serverKeypair = Coneshell.GenerateKeyPair();
        var serverPrivKey = (X25519PrivateKeyParameters)serverKeypair.Private;
        var serverPubKey = (X25519PublicKeyParameters)serverKeypair.Public;

        var deviceUdid = RandomNumberGenerator.GetBytes(16);
        var versionKey = RandomNumberGenerator.GetBytes(20);
        var sessionId = RandomNumberGenerator.GetBytes(16);

        var authInfo = addAuthData ? GetAuthenticationData() : null;
        var coneshell = new ConeshellV4(serverPubKey, versionKey, deviceUdid, sessionId, authInfo);

        instance = coneshell;
        serverPrivateKey = serverPrivKey;
    }

    public static byte[] GetAuthenticationData()
    {
        var authInfo = new byte[0x32];
        authInfo[0] = 0x13;
        authInfo[1] = 0x37;
        RandomNumberGenerator.Fill(authInfo.AsSpan(2, 0x10));
        MD5.HashData(authInfo.AsSpan(2, 0x10)).CopyTo(authInfo.AsSpan(0x12));
        authInfo.AsSpan(2, 0x10).CopyTo(authInfo.AsSpan(0x22));
        return authInfo;
    }

    public static ReadOnlySpan<byte> NonceDerivationCallback(ReadOnlySpan<byte> authenticationData)
    {
        Debug.Assert(authenticationData[0] == 0x13);
        Debug.Assert(authenticationData[1] == 0x37);
        var nonce = authenticationData.Slice(2, 0x10);
        Debug.Assert(authenticationData[0x12..].SequenceEqual(MD5.HashData(nonce)));
        return nonce;
    }

    [TestMethod]
    public void ConeshellV4_ClientServer_ParsesMessage()
    {
        GetRandomConeshell(out var coneshell, out var serverPrivKey);

        var testMessage = "ConeshellTestMessage"u8.ToArray();
        var clientInfo = coneshell.EncryptRequest(testMessage);
        var serverInfo = coneshell.DecryptRequest(clientInfo.Data, serverPrivKey);

        CollectionAssert.AreEqual(clientInfo.SharedSecret, serverInfo.SharedSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testMessage, serverInfo.Data, "Server did not decrypt client request properly.");
    }

    [TestMethod]
    public void ConeshellV4_ClientServer_ParsesMessageWithAuthData()
    {
        GetRandomConeshell(out var coneshell, out var serverPrivKey, true);

        var testMessage = "ConeshellTestMessage"u8.ToArray();
        var clientInfo = coneshell.EncryptRequest(testMessage);
        var serverInfo = coneshell.DecryptRequest(clientInfo.Data, serverPrivKey, NonceDerivationCallback);

        CollectionAssert.AreEqual(clientInfo.SharedSecret, serverInfo.SharedSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(clientInfo.Nonce, serverInfo.Nonce, "Nonce mismatch between client and server.");
        CollectionAssert.AreEqual(testMessage, serverInfo.Data, "Server did not decrypt client request properly.");
    }

    [TestMethod]
    public void ConeshellV4_ServerClient_ParsesMessage()
    {
        GetRandomConeshell(out var coneshell, out _);

        var requestInfo = new ConeshellV4.ConeshellRequestData([], RandomNumberGenerator.GetBytes(32),
            RandomNumberGenerator.GetBytes(16));

        var testMessage = "ConeshellTestMessage"u8.ToArray();
        var encrypted = coneshell.EncryptResponse(testMessage, in requestInfo);
        var decrypted = coneshell.DecryptResponse(encrypted, in requestInfo);

        CollectionAssert.AreEqual(testMessage, decrypted, "Client did not decrypt server response properly.");
    }

    [TestMethod]
    public void ConeshellV4_ServerClient_ParsesMessageCompressed()
    {
        GetRandomConeshell(out var coneshell, out _);

        var requestInfo = new ConeshellV4.ConeshellRequestData([], RandomNumberGenerator.GetBytes(32),
            RandomNumberGenerator.GetBytes(16));

        var testMessage = "ConeshellTestMessage"u8.ToArray();
        var encrypted = coneshell.EncryptResponse(testMessage, in requestInfo, true);
        var decrypted = coneshell.DecryptResponse(encrypted, in requestInfo);

        CollectionAssert.AreEqual(testMessage, decrypted, "Client did not decrypt compressed server response properly.");
    }

    [TestMethod]
    public void ConeshellV4_Both_RoundtripMessageExchange()
    {
        GetRandomConeshell(out var coneshell, out var serverPrivKey);

        var testRequest = "ClientTestRequest"u8.ToArray();
        var testResponse = "ServerTestResponse"u8.ToArray();

        var encryptedRequestInfo = coneshell.EncryptRequest(testRequest);
        var decryptedRequestInfo = coneshell.DecryptRequest(encryptedRequestInfo.Data, serverPrivKey);

        var encryptedResponse = coneshell.EncryptResponse(testResponse, in decryptedRequestInfo);
        var decryptedResponse = coneshell.DecryptResponse(encryptedResponse, in encryptedRequestInfo);

        CollectionAssert.AreEqual(encryptedRequestInfo.SharedSecret, decryptedRequestInfo.SharedSecret, "Shared secret mismatch between client and server.");
        CollectionAssert.AreEqual(testRequest, decryptedRequestInfo.Data, "Server did not decrypt client request properly.");
        CollectionAssert.AreEqual(testResponse, decryptedResponse, "Client did not decrypt server response properly.");
    }
}