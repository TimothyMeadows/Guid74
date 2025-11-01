# Guid74
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/Guid74.svg)](https://www.nuget.org/packages/Guid74/)

Lightweight .NET library to generate UUIDv7 and present them as UUIDv4 facades using a keyed SipHash mask. Useful when you need time-ordered IDs internally but want identifiers that look like random v4 UUIDs for external consumption.

## Install

Install from NuGet

```bash
dotnet add package Guid74
```

## Quick start

Register the library in your application's DI container and configure a seed Guid:

```csharp
services.AddGuid74();
services.Configure<Guid74Options>(o => o.SeedGuid = Guid.Parse("11111111-2222-3333-4444-555555555555"));
```

Resolve the service and use it:

```csharp
var svc = provider.GetRequiredService<Guid74Service>();
var v7 = svc.NewV7();                // generate UUIDv7
var facade = svc.EncodeFacade(v7);   // produce a v4-looking facade
var original = svc.DecodeFacade(facade); // recover v7 (requires same seed)
```

## API

Types

- Guid74Options
  - SeedGuid (Guid) — required seed used to derive SipHash keys.

- Guid74Service
  - NewV7() -> Guid
  - NewV4() -> Guid
  - EncodeFacade(Guid v7) -> Guid
  - DecodeFacade(Guid facadeV4) -> Guid

- Guid74Codec
  - Same public methods as Guid74Service (NewV7, NewV4, EncodeFacade, DecodeFromFacade)

## How it works

- UUIDv7 generation: writes a 48-bit Unix epoch milliseconds timestamp into bytes 0..5 (RFC byte order), fills remaining bytes with randomness, and sets version/variant bits.
- Facade encoding: builds a 10-byte message from the UUID fields (excluding timestamp), computes a SipHash keyed by a seed-derived key, takes the low 48 bits of the hash as a mask, XORs the mask with the timestamp, then marks the UUID as version 4.
- Decoding reverses the mask using the same seed to recover the original timestamp and restores version 7.

## Configuration and secrets

- SeedGuid must be set via Guid74Options. The seed is used to derive SipHash K0/K1 and is critical to decoding facades.
- You may use an Azure GUID such as TenantId or Application (Client)Id as the seed for convenience. Note that these IDs are often public; if the seed must remain secret, store a dedicated GUID in a secret store (Key Vault, environment variable, etc.).

## Notes on security

- The facade masks only the 48-bit timestamp. It is not a general-purpose encryption mechanism.
- The library pins and zeros seed bytes when deriving keys to reduce memory leakage, but you should still manage the seed securely.

## Dependencies

- PinnedMemory
- SipHash

## Contributing

PRs welcome. Please include tests and keep behavior backwards compatible.
