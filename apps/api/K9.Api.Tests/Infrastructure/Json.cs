using System.Text.Json;
using System.Text.Json.Serialization;

namespace K9.Api.Tests.Infrastructure;

public static class Json
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };
}
