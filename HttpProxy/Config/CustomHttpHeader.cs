using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace HttpProxy.Config {
	public interface ICustomHttpHeader {
		string Key { get; }

		string Value { get; }
	}

	public class CustomHttpHeader : ICustomHttpHeader {
		[JsonPropertyName("key")]
		public string Key { get; set; }

		[JsonPropertyName("value")]
		public string Value { get; set; }

		public void Init() {

		}
	}
}
