using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PinnedMemory;
using SipHash;

namespace Guid74
{
    public class Guid74Options
    {
        public Guid SeedGuid { get; set; }
    }

    internal sealed class SeedHolder : IDisposable
    {
        private readonly PinnedMemory<byte> _seedBytes;
        private bool _disposed;

        public SeedHolder(Guid seed)
        {
            if (seed == Guid.Empty) throw new ArgumentException("SeedGuid must be non-empty.", nameof(seed));
            var arr = seed.ToByteArray();
            _seedBytes = new PinnedMemory<byte>(arr, zero: true, locked: true);
        }

        public void DeriveSipKeys(out ulong k0, out ulong k1)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(SeedHolder));
            Span<byte> tmp = stackalloc byte[16];
            tmp = _seedBytes.ToArray();
            k0 = BitConverter.ToUInt64(tmp.Slice(0, 8));
            k1 = BitConverter.ToUInt64(tmp.Slice(8, 8));
            tmp.Clear();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _seedBytes.Dispose();
            _disposed = true;
        }
    }

    internal static class GuidRfcBytes
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToRfcBytes(Guid g, Span<byte> dest16)
        {
            var b = g.ToByteArray();
            dest16[0] = b[3]; dest16[1] = b[2]; dest16[2] = b[1]; dest16[3] = b[0];
            dest16[4] = b[5]; dest16[5] = b[4];
            dest16[6] = b[7]; dest16[7] = b[6];
            dest16[8] = b[8]; dest16[9] = b[9]; dest16[10] = b[10]; dest16[11] = b[11];
            dest16[12] = b[12]; dest16[13] = b[13]; dest16[14] = b[14]; dest16[15] = b[15];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Guid FromRfcBytes(ReadOnlySpan<byte> rfc16)
        {
            Span<byte> b = stackalloc byte[16];
            b[0] = rfc16[3]; b[1] = rfc16[2]; b[2] = rfc16[1]; b[3] = rfc16[0];
            b[4] = rfc16[5]; b[5] = rfc16[4];
            b[6] = rfc16[7]; b[7] = rfc16[6];
            b[8] = rfc16[8]; b[9] = rfc16[9]; b[10] = rfc16[10]; b[11] = rfc16[11];
            b[12] = rfc16[12]; b[13] = rfc16[13]; b[14] = rfc16[14]; b[15] = rfc16[15];
            return new Guid(b);
        }
    }

    public class Guid74Codec
    {
        private readonly SipHashService _sip;

        public Guid74Codec(SipHashService sip) => _sip = sip ?? throw new ArgumentNullException(nameof(sip));

        public Guid NewV4()
        {
            Span<byte> b = stackalloc byte[16];
            RandomNumberGenerator.Fill(b);
            b[6] = (byte)((b[6] & 0x0F) | 0x40);
            b[8] = (byte)((b[8] & 0x3F) | 0x80);
            return GuidRfcBytes.FromRfcBytes(b);
        }

        public Guid NewV7()
        {
            Span<byte> b = stackalloc byte[16];
            RandomNumberGenerator.Fill(b);

            ulong ts = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            b[0] = (byte)(ts >> 40);
            b[1] = (byte)(ts >> 32);
            b[2] = (byte)(ts >> 24);
            b[3] = (byte)(ts >> 16);
            b[4] = (byte)(ts >> 8);
            b[5] = (byte)ts;

            b[6] = (byte)((b[6] & 0x0F) | 0x70);
            b[8] = (byte)((b[8] & 0x3F) | 0x80);

            return GuidRfcBytes.FromRfcBytes(b);
        }

        public Guid EncodeFacade(Guid v7)
        {
            Span<byte> b = stackalloc byte[16];
            GuidRfcBytes.ToRfcBytes(v7, b);
            if (((b[6] >> 4) & 0x0F) != 7)
                throw new ArgumentException("Input must be a UUIDv7.", nameof(v7));

            Span<byte> msg = stackalloc byte[10];
            msg[0] = (byte)(b[6] & 0x0F);
            msg[1] = b[7];
            msg[2] = (byte)(b[8] & 0x3F);
            for (int i = 0; i < 7; i++) msg[3 + i] = b[9 + i];

            ulong sip = _sip.ComputeHash(msg);
            ulong mask48 = sip & 0x0000FFFFFFFFFFFFUL;

            ulong ts = ((ulong)b[0] << 40) | ((ulong)b[1] << 32) |
                       ((ulong)b[2] << 24) | ((ulong)b[3] << 16) |
                       ((ulong)b[4] << 8) | b[5];
            ulong ft = ts ^ mask48;

            b[0] = (byte)(ft >> 40); b[1] = (byte)(ft >> 32);
            b[2] = (byte)(ft >> 24); b[3] = (byte)(ft >> 16);
            b[4] = (byte)(ft >> 8); b[5] = (byte)ft;

            b[6] = (byte)((b[6] & 0x0F) | 0x40);
            b[8] = (byte)((b[8] & 0x3F) | 0x80);

            return GuidRfcBytes.FromRfcBytes(b);
        }

        public Guid DecodeFromFacade(Guid facadeV4)
        {
            Span<byte> b = stackalloc byte[16];
            GuidRfcBytes.ToRfcBytes(facadeV4, b);

            Span<byte> msg = stackalloc byte[10];
            msg[0] = (byte)(b[6] & 0x0F);
            msg[1] = b[7];
            msg[2] = (byte)(b[8] & 0x3F);
            for (int i = 0; i < 7; i++) msg[3 + i] = b[9 + i];

            ulong sip = _sip.ComputeHash(msg);
            ulong mask48 = sip & 0x0000FFFFFFFFFFFFUL;

            ulong ft = ((ulong)b[0] << 40) | ((ulong)b[1] << 32) |
                       ((ulong)b[2] << 24) | ((ulong)b[3] << 16) |
                       ((ulong)b[4] << 8) | b[5];
            ulong ts = ft ^ mask48;

            b[0] = (byte)(ts >> 40); b[1] = (byte)(ts >> 32);
            b[2] = (byte)(ts >> 24); b[3] = (byte)(ts >> 16);
            b[4] = (byte)(ts >> 8); b[5] = (byte)ts;

            b[6] = (byte)((b[6] & 0x0F) | 0x70);
            b[8] = (byte)((b[8] & 0x3F) | 0x80);

            return GuidRfcBytes.FromRfcBytes(b);
        }
    }

    public class Guid74Service
    {
        private readonly Guid74Codec _codec;
        public Guid74Service(Guid74Codec codec) => _codec = codec;

        public Guid NewV7() => _codec.NewV7();
        public Guid NewV4() => _codec.NewV4();
        public Guid EncodeFacade(Guid v7) => _codec.EncodeFacade(v7);
        public Guid DecodeFacade(Guid facadeV4) => _codec.DecodeFromFacade(facadeV4);
    }

    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddGuid74(this IServiceCollection services)
        {
            services.AddSipHash();
            services.AddOptions<SipHashOptions>().Configure<IOptions<Guid74Options>>((sip, g74) =>
            {
                if (g74.Value.SeedGuid == Guid.Empty)
                    throw new ArgumentException("Guid74Options.SeedGuid must be set.");
                using var seed = new SeedHolder(g74.Value.SeedGuid);
                seed.DeriveSipKeys(out var k0, out var k1);
                sip.K0 = k0;
                sip.K1 = k1;
            });

            services.AddSingleton<Guid74Codec>();
            services.AddSingleton<Guid74Service>();
            return services;
        }
    }
}
