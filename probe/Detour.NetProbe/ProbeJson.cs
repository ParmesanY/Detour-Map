using System.Text.Json.Serialization;

namespace Detour.NetProbe;

/// <summary>Source-generated JSON (AOT-safe), snake_case, nulls left out.</summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    ReadCommentHandling = System.Text.Json.JsonCommentHandling.Skip,
    AllowTrailingCommas = true)]
[JsonSerializable(typeof(ProbeReport))]
[JsonSerializable(typeof(TargetResult))]
[JsonSerializable(typeof(TargetList))]
[JsonSerializable(typeof(SendResult))]
[JsonSerializable(typeof(TraceReport))]
public sealed partial class ProbeJson : JsonSerializerContext;
