﻿using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace HttpProxy.Config {
	public interface IProxyConfiguration {
		string Path { get; }

		string Target { get; }

		string OverrideHost { get; }

		bool NewHttpClient { get; }

		IReadOnlyList<ICustomHttpHeader> Headers { get; }

		IImmutableSet<string> RemoveHeaders { get; }

		bool DisableTlsValidation { get; }

		bool UseProxy { get; }

		string ProxyUrl { get; }
	}

	public class ProxyConfiguration : IProxyConfiguration {
		private ImmutableHashSet<string> _removeHeadersCopy;

		[JsonPropertyName("path")]
		public string Path { get; set; }

		[JsonPropertyName("target")]
		public string Target { get; set; }

		[JsonPropertyName("overrideHost")]
		public string OverrideHost { get; set; }

		[JsonPropertyName("newHttpClient")]
		public bool NewHttpClient { get; set; }

		[JsonPropertyName("headers")]
		public List<CustomHttpHeader> Headers { get; set; }

		[JsonPropertyName("removeHeaders")]
		public List<string> RemoveHeaders { get; set; }

		[JsonPropertyName("disableTlsValidation")]
		public bool DisableTlsValidation { get; set; }

		[JsonPropertyName("useProxy")]
		public bool UseProxy { get; set; } = true;

		[JsonPropertyName("proxyUrl")]
		public string ProxyUrl { get; set; }

		public void Init() {
			if (Headers != null) {
				foreach (var h in Headers) {
					h.Init();
				}
			}
			if (Path != null) {
				Path = Path.TrimEnd('/');
			}
			if (Target != null) {
				Target = Target.TrimEnd('/');
			}
			if (RemoveHeaders != null) {
				_removeHeadersCopy = ImmutableHashSet.Create<string>(StringComparer.Ordinal, RemoveHeaders.ToArray());
			}
		}

		IReadOnlyList<ICustomHttpHeader> IProxyConfiguration.Headers => Headers;

		IImmutableSet<string> IProxyConfiguration.RemoveHeaders => _removeHeadersCopy;
	}
}
