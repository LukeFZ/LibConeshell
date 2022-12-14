using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Numerics;

namespace LibConeshell;

public class ConeshellV3 : ConeshellV2
{
    private const int VersionKeyLength = 20;
    private const int VfsCertLength = 472;
    private const int TallyLength = 524;


    private readonly byte[] _versionKey;
    private readonly byte[]? _vfsCert;

    public static ConeshellV3 FromTally(Guid deviceUdid, byte[] tally)
    {
        if (tally.Length != TallyLength)
            throw new ArgumentException($"The tally must be {TallyLength} bytes in length.", nameof(tally));

        return new ConeshellV3(
            Convert.FromHexString(deviceUdid.ToString().Replace("-", "")),
            tally[0x1f8..],
            new X25519PublicKeyParameters(tally[0x1d8..0x1f8].Reverse().ToArray()),
            tally[..0x1d8]);
    }

    public ConeshellV3(byte[] deviceUdid, byte[] versionKey, X25519PublicKeyParameters serverPublicKey, byte[] vfsCert)
        : this(deviceUdid, versionKey, serverPublicKey)
    {
        if (vfsCert.Length != VfsCertLength)
            throw new ArgumentException($"The VFS certificate must be {VfsCertLength} bytes in length.", nameof(vfsCert));

        _vfsCert = vfsCert;
    }

    public ConeshellV3(byte[] deviceUdid, byte[] versionKey, X25519PublicKeyParameters serverPublicKey)
        : this(deviceUdid, versionKey)
    {
        ServerPublicKey = serverPublicKey;
    }

    public ConeshellV3(byte[] deviceUdid, byte[] versionKey)
        : base(deviceUdid)
    {
        if (versionKey.Length != VersionKeyLength)
            throw new ArgumentException($"The version key must be {VersionKeyLength} bytes in length.", nameof(versionKey));

        _versionKey = versionKey;
    }

    public ConeshellV3()
    {
        _versionKey = new byte[20];
    }

    #region Coneshell Message Functions

    protected override uint HeaderMagic => 0x0300DEC0;

    protected override byte[] DeriveDeviceSecret(byte[] sharedSecret)
    {
        if (sharedSecret.Length != SharedSecretLength)
            throw new ArgumentException($"The shared secret must be {SharedSecretLength} bytes in length.", nameof(sharedSecret));

        var result = sharedSecret[..16];

        for (int i = 0; i < 16; i++)
        {
            var udid = DeviceUdid[i];
            var secret = result[i];
            var mixed1 = udid ^ secret;
            var mixed2 = DeviceUdid[mixed1 & 0xf] ^ udid;
            var mixed3 = result[mixed2 & 0xf] ^ udid;
            var mixed4 = _versionKey[mixed3 & 0xf] ^ udid;
            result[mixed4 & 0xf] ^= (byte)mixed1;
            result[mixed3 & 0xf] ^= (byte)mixed2;
            result[mixed2 & 0xf] ^= (byte)mixed4;
            result[mixed1 & 0xf] ^= (byte)mixed3;
        }

        var hash = MD5.Create();
        hash.TransformBlock(sharedSecret, 0, sharedSecret.Length, null, 0);
        hash.TransformBlock(result, 0, result.Length, null, 0);
        hash.TransformFinalBlock(_versionKey, 0, _versionKey.Length);

        return hash.Hash!;
    }

    #endregion

    #region Coneshell VFS Functions

    protected override uint VfsHeaderMagic => 0x03007ADA;

    private static ulong ReadBigEndianULong(BinaryReader reader)
        => BinaryPrimitives.ReadUInt64BigEndian(reader.ReadBytes(8));

    public override byte[] DecryptVfs(byte[] dbData, bool skipVerification = false /* TODO: Not implemented */)
    {
        if (!skipVerification && _vfsCert == null)
            throw new ArgumentException("You need to supply a VFS certificate for signature verification.", nameof(skipVerification));

        var inputStream = new MemoryStream(dbData);
        var inputReader = new BinaryReader(inputStream);

        if (inputReader.ReadUInt32() != VfsHeaderMagic)
            throw new IOException("Invalid database header.");

        var processedData = PreprocessVfs(inputReader, dbData.Length - 4);
        inputReader.Dispose();
        inputStream.Dispose();

        inputStream = new MemoryStream(processedData);
        inputReader = new BinaryReader(inputStream);

        var publicKey = "";
        if (!skipVerification)
        {
            using var encCertStream = new MemoryStream(_vfsCert!);
            using var encCertReader = new BinaryReader(encCertStream);
            encCertReader.BaseStream.Position += 4;

            var transformConstant1 = ReadBigEndianULong(encCertReader);
            var transformConstant2 = ReadBigEndianULong(encCertReader);

            var transformMixed1 = (2 * transformConstant2) | 1;
            var transformMixed2 = transformMixed1 + TransformConstant * (transformMixed1 + transformConstant1);

            var encCert = new uint[0x1c4 / 4];
            for (int i = 0; i < 0x1c4 / 4; i++)
                encCert[i] = encCertReader.ReadUInt32();

            publicKey = DeriveVfsPublicKey(encCert, transformMixed2, transformMixed1);

        }

        return DecryptVfsInternal(processedData, inputReader, skipVerification, publicKey, 4);
    }

    private static byte[] PreprocessVfs(BinaryReader dbReader, int remainingLength)
    {
        const int transformLength = 16;

        unchecked
        {
            var transformInputConstant1 = ReadBigEndianULong(dbReader);
            var transformInputConstant2 = ReadBigEndianULong(dbReader);

            dbReader.BaseStream.Position += 4; // gcmAdd1

            var transformInputConstant3 = ReadBigEndianULong(dbReader);
            var transformInputConstant4 = ReadBigEndianULong(dbReader);

            var transformMixed1 = (2 * transformInputConstant4) | 1; 
            var transformMixed2 = transformMixed1 + TransformConstant * (transformMixed1 + transformInputConstant3); 
            var transformMixed3 = (2 * transformInputConstant2) | 1; 
            var transformMixed4 = transformMixed3 + TransformConstant * (transformMixed3 + transformInputConstant1);

            var transformArray = new byte[transformLength];

            for (int i = 0; i < transformLength; i++)
            {
                var transformCombined1 = transformMixed1 + TransformConstant * transformMixed2;
                var transformRotated1 = BitOperations.RotateRight((uint)((transformMixed2 ^ (transformMixed2 >> 18)) >> 27), (int)(transformMixed2 >> 59));
                var transformRotated2 = BitOperations.RotateRight((uint)((transformMixed4 ^ (transformMixed4 >> 18)) >> 27), (int)(transformMixed4 >> 59));
                transformArray[i] = (byte)(transformRotated1 ^ transformRotated2);

                if (transformRotated2 != 0)
                {
                    var (transformLoopBase1, transformLoopAdd1) = InternalVfsPreprocessLoop(transformMixed1, transformRotated2);
                    transformMixed2 = transformLoopBase1 + transformLoopAdd1 * transformCombined1;
                }
                else
                    transformMixed2 = transformCombined1;

                var transformCombined2 = transformMixed3 + TransformConstant * transformMixed4;

                if (transformRotated1 != 0)
                {
                    var (transformLoopBase2, transformLoopAdd2) = InternalVfsPreprocessLoop(transformMixed3, transformRotated1);
                    transformMixed4 = transformLoopBase2 + transformLoopAdd2 * transformCombined2;
                }
                else
                    transformMixed4 = transformCombined2;
            }

            dbReader.BaseStream.Position = 4;

            var processedData = dbReader.ReadBytes(remainingLength);

            for (int i = 0; i < 4; i++)
                processedData[i] = processedData[16 + i];

            for (int i = 0; i < 16; i++)
                processedData[4 + i] = transformArray[i];

            return processedData;
        }
    }

    private static (ulong transformBase, ulong transformAdd) InternalVfsPreprocessLoop(ulong input, ulong loopInput)
    {
        const ulong transformConstant = 0x5851F42D4C957F2D;

        unchecked
        {
            ulong transformBase = 0;
            ulong transformAdd = 1;

            var loopBase = input;
            var loopAdd = transformConstant;
            var loopCondition = (uint)loopInput;

            do
            {
                if ((loopCondition & 1) == 1)
                {
                    transformAdd *= loopAdd;
                    transformBase = loopBase + loopAdd * transformBase;
                }

                loopBase *= loopAdd + 1;
                loopAdd *= loopAdd;
                loopCondition >>= 1;
            } while (loopCondition != 0);

            return (transformBase, transformAdd);
        }
    }

    #endregion
}