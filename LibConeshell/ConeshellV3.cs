using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Numerics;

namespace LibConeshell;

public class ConeshellV3 : ConeshellV2
{
    private readonly byte[] _versionKey;

    public static ConeshellV3 FromTally(Guid deviceUdid, byte[] tally)
    {
        if (tally.Length != 524)
            throw new ArgumentException("The tally must be 524 bytes in length.", nameof(tally));

        return new ConeshellV3(
            Convert.FromHexString(deviceUdid.ToString().Replace("-", "")),
            tally[0x1f8..],
            new X25519PublicKeyParameters(tally[0x1d8..0x1f8].Reverse().ToArray()));
    }

    public ConeshellV3(byte[] deviceUdid, byte[] versionKey, X25519PublicKeyParameters serverPublicKey)
        : this(deviceUdid, versionKey)
    {
        ServerPublicKey = serverPublicKey;
    }

    public ConeshellV3(byte[] deviceUdid, byte[] versionKey)
        : base(deviceUdid)
    {
        if (versionKey.Length != 20)
            throw new ArgumentException("The version key must be 20 bytes in length.", nameof(versionKey));

        _versionKey = versionKey;
    }

    #region Coneshell Message Functions

    protected override uint HeaderMagic => 0x0300DEC0;

    protected override byte[] DeriveDeviceSecret(byte[] sharedSecret)
    {
        if (sharedSecret.Length != 32)
            throw new InvalidDataException("The shared secret must be 32 bytes in length.");

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

    public override byte[] DecryptVfs(byte[] dbData, bool skipVerification = false /* TODO: Not implemented */)
    {
        var inputStream = new MemoryStream(dbData);
        var inputReader = new BinaryReader(inputStream);

        if (inputReader.ReadUInt32() != VfsHeaderMagic)
            throw new InvalidDataException("Invalid database header.");

        var processedData = PreprocessVfs(inputReader, dbData.Length - 4);
        inputReader.Dispose();
        inputStream.Dispose();

        inputStream = new MemoryStream(processedData);
        inputReader = new BinaryReader(inputStream);

        return DecryptVfsInternal(processedData, inputReader, true, 4);
    }

    private static byte[] PreprocessVfs(BinaryReader dbReader, int remainingLength)
    {
        const ulong transformConstant = 0x5851F42D4C957F2D;
        const int transformLength = 16;

        ulong ReadBigEndianULong(BinaryReader reader)
            => BinaryPrimitives.ReadUInt64BigEndian(reader.ReadBytes(8));

        unchecked
        {
            var transformInputConstant1 = ReadBigEndianULong(dbReader);
            var transformInputConstant2 = ReadBigEndianULong(dbReader);

            dbReader.BaseStream.Position += 4; // gcmAdd1

            var transformInputConstant3 = ReadBigEndianULong(dbReader);
            var transformInputConstant4 = ReadBigEndianULong(dbReader);

            var transformMixed1 = (2 * transformInputConstant4) | 1; 
            var transformMixed2 = transformMixed1 + transformConstant * (transformMixed1 + transformInputConstant3); 
            var transformMixed3 = (2 * transformInputConstant2) | 1; 
            var transformMixed4 = transformMixed3 + transformConstant * (transformMixed3 + transformInputConstant1);

            var transformArray = new byte[transformLength];

            for (int i = 0; i < transformLength; i++)
            {
                var transformCombined1 = transformMixed1 + transformConstant * transformMixed2;
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

                var transformCombined2 = transformMixed3 + transformConstant * transformMixed4;

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