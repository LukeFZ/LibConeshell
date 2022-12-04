using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

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

    protected static byte[] AesCtrCryptInternal(byte[] message, byte[] key, byte[] iv)
    {
        if (key.Length != 16)
            throw new ArgumentException("The key must be 16 bytes in length.", nameof(key));

        if (iv.Length != 16)
            throw new ArgumentException("The IV must be 16 bytes in length.", nameof(iv));

        var aes = Aes.Create();
        aes.KeySize = 128;
        aes.Padding = PaddingMode.None;
        aes.Mode = CipherMode.ECB;

        var counter = (byte[])iv.Clone();

        var xorMask = new Queue<byte>();
        var transform = aes.CreateEncryptor(key, new byte[16]);

        using var inputStream = new MemoryStream(message);
        using var outputStream = new MemoryStream();

        int byteRead;
        while ((byteRead = inputStream.ReadByte()) != -1)
        {
            if (xorMask.Count == 0)
            {
                var ctrBlock = new byte[16];

                transform.TransformBlock(counter, 0, counter.Length, ctrBlock, 0);

                for (var j = counter.Length - 1; j >= 0; j--)
                {
                    if (++counter[j] != 0)
                        break;
                }

                foreach (var ctrByte in ctrBlock)
                    xorMask.Enqueue(ctrByte);
            }

            var ctrMask = xorMask.Dequeue();
            outputStream.WriteByte((byte)((byte)byteRead ^ ctrMask));
        }

        return outputStream.ToArray();
    }

    protected static byte[] GenerateSharedSecret(X25519PublicKeyParameters pubKey, X25519PrivateKeyParameters privKey)
    {
        var secret = new byte[X25519PrivateKeyParameters.SecretSize];
        privKey.GenerateSecret(pubKey, secret, 0);

        return secret;
    }
}