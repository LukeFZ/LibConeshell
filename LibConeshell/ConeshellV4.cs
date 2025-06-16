using K4os.Compression.LZ4;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace LibConeshell;

public class ConeshellV4 : Coneshell
{
    private readonly X25519PublicKeyParameters _serverPublicKey;
    private readonly byte[] _versionKey;
    private readonly byte[] _deviceUuid;
    private readonly byte[] _sessionId;
    private readonly byte[]? _authInfo;

    public ConeshellV4(X25519PublicKeyParameters serverPublicKey, byte[] versionKey, byte[] deviceUuid, byte[] sessionId, byte[]? authInfo = null)
    {
        if (versionKey.Length != 20)
            throw new ArgumentException("Version key must be 20 bytes in length.", nameof(versionKey));

        if (deviceUuid.Length != 16)
            throw new ArgumentException("Device UUID must be 16 bytes in length.", nameof(deviceUuid));

        if (sessionId.Length != 16)
            throw new ArgumentException("Session ID must be 16 bytes in length.", nameof(sessionId));

        if (authInfo != null && authInfo.Length != 50)
            throw new ArgumentException("Auth info must be 50 bytes in length.", nameof(authInfo));

        _serverPublicKey = serverPublicKey;
        _versionKey = versionKey;
        _deviceUuid = deviceUuid;
        _sessionId = sessionId;
        _authInfo = authInfo;
    }

    public static ConeshellV4 FromCommonHeader(ReadOnlySpan<byte> commonHeader, byte[] deviceUuid, byte[] sessionId, byte[]? authInfo = null)
    {
        var header = MemoryMarshal.Read<CommonHeader>(commonHeader);
        ((Span<byte>)header.ServerPublicKey).Reverse();

        var serverPublicKey = new X25519PublicKeyParameters(header.ServerPublicKey);
        return new ConeshellV4(serverPublicKey, ((ReadOnlySpan<byte>)header.Salt).ToArray(), deviceUuid, sessionId, authInfo);
    }

    static ConeshellV4()
    {
        Debug.Assert(Unsafe.SizeOf<RequestHeader>() == RequestHeader.HeaderSize);
        Debug.Assert(Unsafe.SizeOf<ResponseHeader>() == ResponseHeader.HeaderSize);
    }

    private const int GcmKeySize = MD5.HashSizeInBytes;
    private const int GcmTagSize = 16;

    private static GcmBlockCipher CreateAesGcmCipher(bool encrypt, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        Debug.Assert(key.Length == GcmKeySize);
        Debug.Assert(tag.Length == GcmTagSize);

        var gcm = new GcmBlockCipher(new AesEngine());
        gcm.Init(encrypt,
            new AeadParameters(new KeyParameter(key),
                tag.Length * 8,
                nonce.ToArray(),
                associatedData.ToArray()
            )
        );

        return gcm;
    }

    private static void EncryptAesGcm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> data,
        Span<byte> encrypted, 
        Span<byte> tag)
    {
        var cipher = CreateAesGcmCipher(true, key, nonce, tag, associatedData);

        var encryptedWithTag = new byte[data.Length + GcmTagSize].AsSpan();
        var processed = cipher.ProcessBytes(data, encryptedWithTag);
        cipher.DoFinal(encryptedWithTag[processed..]);

        encryptedWithTag[..data.Length].CopyTo(encrypted);
        encryptedWithTag[data.Length..].CopyTo(tag);
    }

    private static void DecryptAesGcm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> tag,
        Span<byte> decrypted)
    {
        var cipher = CreateAesGcmCipher(false, key, nonce, tag, associatedData);

        var encryptedWithTag = new byte[data.Length + GcmTagSize].AsSpan();
        data.CopyTo(encryptedWithTag);
        tag.CopyTo(encryptedWithTag[data.Length..]);

        var processed = cipher.ProcessBytes(encryptedWithTag, decrypted);
        cipher.DoFinal(decrypted[processed..]);
    }

    private void ScrambleData(Span<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> key2)
    {
        Debug.Assert(data.Length >= 16);
        Debug.Assert(key.Length >= 16);

        for (int i = 0; i < 16; i++)
        {
            var kb = key[i];
            var db = data[i];
            var mixed1 = (byte)(kb ^ db);
            var mixed2 = (byte)(key2[mixed1 & 0xF] ^ kb);
            var mixed3 = (byte)(data[mixed2 & 0xF] ^ kb);
            var mixed4 = (byte)(_versionKey[mixed3 & 0xF] ^ kb);
            data[mixed2 & 0xF] ^= mixed1;
            data[mixed3 & 0xF] ^= mixed2;
            data[mixed4 & 0xF] ^= mixed3;
            data[mixed1 & 0xF] ^= mixed4;
        }
    }

    private void DeriveRequestGcmKey(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> scrambleKey, Span<byte> gcmKey)
    {
        Debug.Assert(gcmKey.Length == GcmKeySize);

        var scrambledData = (stackalloc byte[16]);
        sharedSecret[..16].CopyTo(scrambledData);
        ScrambleData(scrambledData, scrambleKey, sharedSecret);

        var hash = new MD5Digest();
        hash.BlockUpdate(scrambledData);
        hash.BlockUpdate(sharedSecret);
        hash.BlockUpdate(scrambleKey);
        hash.BlockUpdate(_versionKey);
        hash.DoFinal(gcmKey);
    }

    private void DeriveRequestGcmNonce(ReadOnlySpan<byte> clientPublicKey, Span<byte> gcmNonce)
    {
        Debug.Assert(gcmNonce.Length == 16);

        var hash = new MD5Digest();
        hash.BlockUpdate(clientPublicKey);
        hash.BlockUpdate(_sessionId);
        hash.BlockUpdate(_deviceUuid);
        hash.DoFinal(gcmNonce);
    }

    private void DeriveRequestAssociatedData(Span<byte> associatedData)
    {
        Debug.Assert(associatedData.Length == 0x34);

        _versionKey.CopyTo(associatedData);
        _sessionId.CopyTo(associatedData[0x14..]);
        _deviceUuid.CopyTo(associatedData[0x24..]);
    }

    public ConeshellRequestData EncryptRequest(ReadOnlySpan<byte> data, X25519PrivateKeyParameters? clientPrivateKey = null)
    {
        clientPrivateKey ??= (X25519PrivateKeyParameters)GenerateKeyPair().Private;
        var sharedSecret = GenerateSharedSecret(_serverPublicKey, clientPrivateKey);

        var requestHeader = new RequestHeader();
        clientPrivateKey.GeneratePublicKey().Encode(requestHeader.ClientPublicKey);

        var nonce = (stackalloc byte[16]);
        var scrambleKey = (stackalloc byte[16]);

        var authenticationData = (stackalloc byte[0x24]);
        authenticationData[1] = 0;

        if (_authInfo != null)
        {
            authenticationData[0] = 1;

            var authInfo = _authInfo.AsSpan();
            authInfo[..0x22].CopyTo(authenticationData[2..]);
            authInfo[0x22..].CopyTo(nonce);

            {
                var hash = new MD5Digest();
                hash.BlockUpdate(_sessionId);
                hash.BlockUpdate(nonce);
                hash.BlockUpdate(_deviceUuid);
                hash.DoFinal(scrambleKey);
            }
        }
        else
        {
            authenticationData[0] = 0;

            _deviceUuid.CopyTo(nonce);
            _deviceUuid.CopyTo(scrambleKey);
            _deviceUuid.CopyTo(authenticationData[2..]);
            RandomNumberGenerator.Fill(authenticationData[0x12..]);
        }

        var encryptedAuthenticationData = AesCtrCryptInternal(
            authenticationData,
            sharedSecret,
            requestHeader.ClientPublicKey[..16]
        );

        encryptedAuthenticationData.CopyTo(requestHeader.EncryptedAuthenticationInfo);

        var gcmKey = (stackalloc byte[16]);
        var gcmNonce = (stackalloc byte[16]);
        var gcmAssociatedData = (stackalloc byte[0x34]);

        DeriveRequestGcmKey(sharedSecret, scrambleKey, gcmKey);
        DeriveRequestGcmNonce(requestHeader.ClientPublicKey, gcmNonce);
        DeriveRequestAssociatedData(gcmAssociatedData);

        var encryptedData = new byte[data.Length + RequestHeader.HeaderSize];
        EncryptAesGcm(gcmKey,
            gcmNonce,
            gcmAssociatedData,
            data,
            encryptedData.AsSpan(RequestHeader.HeaderSize),
            requestHeader.GcmTag
        );

        requestHeader.Size = encryptedData.Length - 0x4;
        MemoryMarshal.Write(encryptedData, requestHeader);

        return new ConeshellRequestData(encryptedData, sharedSecret, nonce.ToArray());
    }

    public ConeshellRequestData DecryptRequest(ReadOnlySpan<byte> data, X25519PrivateKeyParameters serverPrivateKey, Func<ReadOnlySpan<byte>, ReadOnlySpan<byte>>? deriveNonceCallback = null)
    {
        var requestHeader = MemoryMarshal.Read<RequestHeader>(data);
        var encryptedData = data[RequestHeader.HeaderSize..];

        var clientPublicKey = new X25519PublicKeyParameters(requestHeader.ClientPublicKey);
        var sharedSecret = GenerateSharedSecret(clientPublicKey, serverPrivateKey);

        var authenticationInfo = AesCtrCryptInternal(requestHeader.EncryptedAuthenticationInfo, sharedSecret,
            requestHeader.ClientPublicKey[..16]).AsSpan();

        var scrambleKey = (stackalloc byte[16]);
        var authNonce = (stackalloc byte[16]);

        if (authenticationInfo[0] == 1)
        {
            if (deriveNonceCallback == null)
                throw new ArgumentException("Nonce derivation callback must be provided for authenticated requests.", nameof(deriveNonceCallback));

            var nonce = deriveNonceCallback(authenticationInfo[2..]);
            if (nonce.Length != 16)
                throw new CryptographicException("Derived nonce must be 16 bytes in length.");

            {
                var hash = new MD5Digest();
                hash.BlockUpdate(_sessionId);
                hash.BlockUpdate(nonce);
                hash.BlockUpdate(_deviceUuid);
                hash.DoFinal(scrambleKey);
            }

            nonce.CopyTo(authNonce);
        }
        else
        {
            var uuid = authenticationInfo.Slice(2, 0x10);
            if (!uuid.SequenceEqual(_deviceUuid))
                throw new CryptographicException("UUID mismatch in request authentication.");

            uuid.CopyTo(scrambleKey);
            uuid.CopyTo(authNonce);
        }

        var gcmKey = (stackalloc byte[16]);
        var gcmNonce = (stackalloc byte[16]);
        var gcmAssociatedData = (stackalloc byte[0x34]);

        DeriveRequestGcmKey(sharedSecret, scrambleKey, gcmKey);
        DeriveRequestGcmNonce(requestHeader.ClientPublicKey, gcmNonce);
        DeriveRequestAssociatedData(gcmAssociatedData);

        var decryptedData = new byte[encryptedData.Length];
        DecryptAesGcm(
            gcmKey,
            gcmNonce,
            gcmAssociatedData,
            encryptedData,
            requestHeader.GcmTag,
            decryptedData
        );

        return new ConeshellRequestData(decryptedData, sharedSecret, authNonce.ToArray());
    }

    private void DeriveResponseGcmKey(ref readonly ConeshellRequestData requestData, Span<byte> gcmKey)
    {
        Debug.Assert(gcmKey.Length == GcmKeySize);

        var hash = new MD5Digest();
        hash.BlockUpdate(requestData.SharedSecret);
        hash.BlockUpdate(_sessionId);
        hash.BlockUpdate(requestData.Nonce);
        hash.DoFinal(gcmKey);
    }

    private void DeriveResponseGcmAssociatedData(ref readonly ConeshellRequestData requestData, Span<byte> associatedData)
    {
        Debug.Assert(associatedData.Length == 0x20);
        _sessionId.CopyTo(associatedData);
        requestData.Nonce.CopyTo(associatedData[0x10..]);
    }

    public byte[] EncryptResponse(ReadOnlySpan<byte> data, ref readonly ConeshellRequestData requestData, bool shouldCompress = false)
    {
        var responseHeader = new ResponseHeader();
        RandomNumberGenerator.Fill(responseHeader.GcmNonce);

        ReadOnlySpan<byte> dataToEncrypt;
        if (shouldCompress)
        {
            responseHeader.DecompressedSize = data.Length;

            var compressedData = new byte[LZ4Codec.MaximumOutputSize(data.Length)];
            var compressedSize = LZ4Codec.Encode(data, compressedData);

            dataToEncrypt = compressedData.AsSpan(0, compressedSize);
        }
        else
        {
            responseHeader.DecompressedSize = 0;
            dataToEncrypt = data;
        }

        var gcmKey = (stackalloc byte[GcmKeySize]);
        DeriveResponseGcmKey(in requestData, gcmKey);

        var associatedData = (stackalloc byte[0x20]);
        DeriveResponseGcmAssociatedData(in requestData, associatedData);

        var response = new byte[ResponseHeader.HeaderSize + dataToEncrypt.Length];
        EncryptAesGcm(
            gcmKey,
            responseHeader.GcmNonce,
            associatedData,
            dataToEncrypt,
            response.AsSpan(ResponseHeader.HeaderSize),
            responseHeader.GcmTag
        );

        MemoryMarshal.Write(response, responseHeader);
        return response;
    }

    public byte[] DecryptResponse(ReadOnlySpan<byte> response, ref readonly ConeshellRequestData requestData)
    {
        var responseHeader = MemoryMarshal.Read<ResponseHeader>(response);
        var encryptedData = response[ResponseHeader.HeaderSize..];

        var isCompressed = responseHeader.DecompressedSize != 0;

        var gcmKey = (stackalloc byte[GcmKeySize]);
        DeriveResponseGcmKey(in requestData, gcmKey);

        var associatedData = (stackalloc byte[0x20]);
        DeriveResponseGcmAssociatedData(in requestData, associatedData);

        var decrypted = new byte[encryptedData.Length];
        DecryptAesGcm(
            gcmKey,
            responseHeader.GcmNonce,
            associatedData,
            encryptedData,
            responseHeader.GcmTag,
            decrypted
        );

        if (isCompressed)
        {
            var outputBuffer = new byte[responseHeader.DecompressedSize];
            LZ4Codec.Decode(decrypted, outputBuffer);
            return outputBuffer;
        }

        return decrypted;
    }

    public record struct ConeshellRequestData(byte[] Data, byte[] SharedSecret, byte[] Nonce);
}

[StructLayout(LayoutKind.Sequential)]
file struct RequestHeader
{
    public const int HeaderSize = 0x58;

    public int Size;
    public PublicKey ClientPublicKey;
    public EncryptedAuthInfo EncryptedAuthenticationInfo;
    public Buffer16 GcmTag;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
file struct ResponseHeader
{
    public const int HeaderSize = 0x24;

    public int DecompressedSize;
    public Buffer16 GcmNonce;
    public Buffer16 GcmTag;
}

[StructLayout(LayoutKind.Sequential)]
file struct CommonHeader
{
    public PublicKey ServerPublicKey;
    public HashSalt Salt;
}

[InlineArray(32)]
file struct PublicKey
{
    private byte _value;
}

[InlineArray(20)]
file struct HashSalt
{
    private byte _value;
}

[InlineArray(16)]
file struct Buffer16
{
    private byte _value;
}

[InlineArray(36)]
file struct EncryptedAuthInfo
{
    private byte _value;
}