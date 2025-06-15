using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace LibConeshell;

public abstract class Coneshell
{
    protected const int SharedSecretLength = 32;
    protected const int DeviceUdidLength = 16;

    public static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var keygen = new X25519KeyPairGenerator();
        keygen.Init(new X25519KeyGenerationParameters(new SecureRandom()));

        var keypair = keygen.GenerateKeyPair();
        if (keypair == null)
            throw new CryptographicException("Failed to generate X25519 keypair.");

        return keypair;
    }

    protected static byte[] AesCtrCryptInternal(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != 16 && key.Length != 32)
            throw new ArgumentException("The key must be 16 bytes in length.", nameof(key));

        if (iv.Length != 16)
            throw new ArgumentException("The IV must be 16 bytes in length.", nameof(iv));

        var ctr = new BufferedBlockCipher(new SicBlockCipher(new AesEngine()));
        var output = new byte[ctr.GetOutputSize(message.Length)];

        ctr.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
        ctr.DoFinal(message, output);

        return output;
    }

    protected static byte[] GenerateSharedSecret(X25519PublicKeyParameters pubKey, X25519PrivateKeyParameters privKey)
    {
        var secret = new byte[X25519PrivateKeyParameters.SecretSize];
        privKey.GenerateSecret(pubKey, secret);

        return secret;
    }
}