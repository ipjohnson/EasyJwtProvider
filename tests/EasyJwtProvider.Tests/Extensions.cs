using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace EasyJwtProvider.Tests
{
    public static class Extensions
    {
        public static Stream SerializeToStream<T>(this T value)
        {
            MemoryStream returnStream = new MemoryStream();

            using (var text = new StreamWriter(returnStream))
            {
                using (var jsonStream = new JsonTextWriter(text))
                {
                    var serializer = new JsonSerializer();

                    serializer.Serialize(jsonStream, value);
                }
            }

            return new MemoryStream(returnStream.ToArray());
        }

        public static T Deserialize<T>(this byte[] bytes)
        {
            var newMemoryStream = new MemoryStream(bytes);

            using (var text = new StreamReader(newMemoryStream))
            {
                using (var jsonStream = new JsonTextReader(text))
                {
                    var serializer = new JsonSerializer();

                    return serializer.Deserialize<T>(jsonStream);
                }
            }
        }

        public static T DeserializeFromMemoryStream<T>(this MemoryStream stream)
        {
            var newMemoryStream = new MemoryStream(stream.ToArray());

            using (var text = new StreamReader(newMemoryStream))
            {
                using (var jsonStream = new JsonTextReader(text))
                {
                    var serializer = new JsonSerializer();

                    return serializer.Deserialize<T>(jsonStream);
                }
            }
        }
    }
}
