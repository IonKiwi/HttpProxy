using HttpProxy.Config;
using HttpProxy.Utilities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HttpProxy.Core {
	public class ReverseProxyMiddleware {
		private readonly object _syncRoot = new object();
		private Dictionary<string, HttpMessageHandler> _httpHandlers = new Dictionary<string, HttpMessageHandler>(StringComparer.Ordinal);

		private HttpClient GetHttpClient(IProxyConfiguration proxy) {
			if (proxy.NewHttpClient) {
				return new HttpClient(CreateHandler(proxy));
			}
			if (_httpHandlers.TryGetValue(proxy.Target, out var httpHandler)) {
				return new HttpClient(httpHandler);
			}
			lock (_syncRoot) {
				if (_httpHandlers.TryGetValue(proxy.Target, out httpHandler)) {
					return new HttpClient(httpHandler);
				}

				httpHandler = CreateHandler(proxy);
				_logger.LogInformation("HttpMessageHandler created");

				var newDictionary = new Dictionary<string, HttpMessageHandler>(StringComparer.Ordinal);
				foreach (var kv in _httpHandlers) {
					newDictionary.Add(kv.Key, kv.Value);
				}
				newDictionary.Add(proxy.Target, httpHandler);
				Interlocked.MemoryBarrier();
				_httpHandlers = newDictionary;
			}
			return new HttpClient(httpHandler);
		}

		private HttpMessageHandler CreateHandler(IProxyConfiguration proxy) {
			var handler = new SocketsHttpHandler() {
				AllowAutoRedirect = false,
				UseProxy = true,
				UseCookies = false,
				AutomaticDecompression = DecompressionMethods.None,
			};
			handler.SslOptions.ApplicationProtocols = new List<SslApplicationProtocol>() { SslApplicationProtocol.Http11, SslApplicationProtocol.Http2 };
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
				handler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
			}
			else {
				handler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13;
			}
			if (proxy.DisableTlsValidation) {
				handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
			}
			else {
				handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => ValidateServerCertificate(certificate, chain, sslPolicyErrors, proxy);
			}
			handler.UseProxy = proxy.UseProxy;
			if (!string.IsNullOrEmpty(proxy.ProxyUrl)) {
				if (!Uri.TryCreate(proxy.ProxyUrl, UriKind.Absolute, out var proxyUri)) {
					throw new InvalidOperationException($"Invalid proxy url '{proxy.ProxyUrl}'.");
				}
				handler.Proxy = new CustomProxy(proxyUri);
			}

			//var handler = new HttpClientHandler() {
			//	AllowAutoRedirect = false,
			//	UseProxy = true,
			//	UseCookies = false,
			//	AutomaticDecompression = DecompressionMethods.None,
			//	SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
			//	ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => ValidateServerCertificate(certificate, chain, sslPolicyErrors, proxy)
			//};

			return handler;
		}

		private sealed class CustomProxy : IWebProxy {
			private readonly Uri _proxyUri;

			public CustomProxy(Uri proxyUri) {
				_proxyUri = proxyUri;
			}

			public ICredentials Credentials { get; set; }

			public Uri GetProxy(Uri destination) {
				return _proxyUri;
			}

			public bool IsBypassed(Uri host) {
				return false;
			}
		}

		private readonly RequestDelegate _nextMiddleware;
		private readonly IFarmSettings _settings;
		private readonly ILogger _logger;

		public ReverseProxyMiddleware(RequestDelegate nextMiddleware, IFarmSettings settings, ILoggerFactory logger) {
			_nextMiddleware = nextMiddleware;
			_settings = settings;
			_logger = logger.CreateLogger<ReverseProxyMiddleware>();
		}

		public async Task Invoke(HttpContext context) {
			string path = context.Request.Path;
			if (path != null) {
				foreach (var s in _settings.Proxy) {
					if (path.StartsWith(s.Path, StringComparison.OrdinalIgnoreCase) && (s.Path.Length == path.Length || path[s.Path.Length] == '/')) {
						await Proxy(s, context);
						return;
					}
				}
			}

			await _nextMiddleware(context);
		}

		private void LogInvalidCertificate(X509Certificate certificate, SslPolicyErrors sslPolicyErrors, X509Chain chain) {
			string policy = string.Empty;
			if (chain != null && chain.ChainPolicy != null) {
				policy = "RevocationMode: " + chain.ChainPolicy.RevocationMode + ", RevocationFlag: " + chain.ChainPolicy.RevocationFlag + ", VerificationFlags: " + chain.ChainPolicy.VerificationFlags;
			}

			string chainErrors = string.Empty;
			if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0) {
				if (chain != null && chain.ChainStatus != null) {
					foreach (X509ChainStatus status in chain.ChainStatus) {
						if (!string.IsNullOrEmpty(chainErrors)) {
							chainErrors += "\r\n";
						}
						chainErrors += status.Status.ToString() + ": " + status.StatusInformation;
					}
				}
			}

			string chainElements = string.Empty;
			for (var i = 0; i < chain.ChainElements.Count; i++) {
				X509ChainElement cel = chain.ChainElements[i];
				if (cel.ChainElementStatus != null && cel.ChainElementStatus.Length > 0) {
					if (!string.IsNullOrEmpty(chainElements)) {
						chainElements += "\r\n";
					}

					string cName = string.Empty;
					if (cel.Certificate != null) {
						cName = cel.Certificate.Subject;
					}

					chainElements += cName + ":";

					foreach (X509ChainStatus status in cel.ChainElementStatus) {
						if (status.Status == X509ChainStatusFlags.NotTimeValid && cel.Certificate != null) {
							chainElements += "\r\n" + status.Status.ToString() + ": " + cel.Certificate.NotBefore.ToString("yyyy-MM-dd HH:mm:ss") + " - " + cel.Certificate.NotAfter.ToString("yyyy-MM-dd HH:mm:ss") + ": " + status.StatusInformation;
						}
						else {
							chainElements += "\r\n" + status.Status.ToString() + ": " + status.StatusInformation;
						}
					}
				}
			}

			_logger.LogWarning(string.Format("Failed to validate certificate '{0}'. policy: {1}, errorType: {2}\r\nchainErrors:\r\n{3}\r\nchainElements:\r\n{4}", certificate.Subject, policy, sslPolicyErrors.ToString(), chainErrors, chainElements));
		}

		private void LogInvalidCertificate(X509Certificate certificate, X509Chain chain) {
			string policyInfo = string.Empty;
			if (chain.ChainPolicy != null) {
				policyInfo = "RevocationMode: " + chain.ChainPolicy.RevocationMode + ", RevocationFlag: " + chain.ChainPolicy.RevocationFlag + ", VerificationFlags: " + chain.ChainPolicy.VerificationFlags;
			}

			string chainErrors = string.Empty;
			if (chain.ChainStatus != null) {
				foreach (X509ChainStatus status in chain.ChainStatus) {
					if (!string.IsNullOrEmpty(chainErrors)) {
						chainErrors += "\r\n";
					}
					chainErrors += status.Status.ToString() + ": " + status.StatusInformation;
				}
			}

			string chainElements = string.Empty;
			for (var i = 0; i < chain.ChainElements.Count; i++) {
				X509ChainElement cel = chain.ChainElements[i];
				if (cel.ChainElementStatus != null && cel.ChainElementStatus.Length > 0) {
					if (!string.IsNullOrEmpty(chainElements)) {
						chainElements += "\r\n";
					}

					string cName = string.Empty;
					if (cel.Certificate != null) {
						cName = cel.Certificate.Subject;
					}

					chainElements += cName + ":";

					foreach (X509ChainStatus status in cel.ChainElementStatus) {
						if (status.Status == X509ChainStatusFlags.NotTimeValid && cel.Certificate != null) {
							chainElements += "\r\n" + status.Status.ToString() + ": " + cel.Certificate.NotBefore.ToString("yyyy-MM-dd HH:mm:ss") + " - " + cel.Certificate.NotAfter.ToString("yyyy-MM-dd HH:mm:ss") + ": " + status.StatusInformation;
						}
						else {
							chainElements += "\r\n" + status.Status.ToString() + ": " + status.StatusInformation;
						}
					}
				}
			}

			_logger.LogWarning(string.Format("Failed to validate certificate '{0}'. policy: {1}\r\nchainErrors:\r\n{2}\r\nchainElements:\r\n{3}", certificate.Subject, policyInfo, chainErrors, chainElements));
		}

		private void LogValidCertificate(X509Certificate certificate, X509Chain chain) {
			string policy = string.Empty;
			if (chain != null && chain.ChainPolicy != null) {
				policy = "RevocationMode: " + chain.ChainPolicy.RevocationMode + ", RevocationFlag: " + chain.ChainPolicy.RevocationFlag + ", VerificationFlags: " + chain.ChainPolicy.VerificationFlags;
			}
			_logger.LogDebug(string.Format("Successfully validated certificate '{0}'. policy: {1}", certificate.Subject, policy));
		}

		private bool ValidateServerCertificate(X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors, IProxyConfiguration proxy) {
			// special handling for IP SAN
			if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateNameMismatch) {
				var certificate2 = (X509Certificate2)certificate;

				X509Chain chain2 = new X509Chain();
				chain2.ChainPolicy = chain.ChainPolicy;
				var result = chain2.Build(certificate2);
				if (!result) {
					LogInvalidCertificate(certificate, chain2);
					return false;
				}

				HashSet<string> serverIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
				HashSet<string> serverNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
				var uccSan = certificate2.Extensions["2.5.29.17"];
				if (uccSan != null) {
					foreach (string nvp in uccSan.Format(true).Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) {
						if (nvp.StartsWith("IP Address=", StringComparison.Ordinal)) {
							var serverName = nvp.Substring(11);
							if (!serverIps.Contains(serverName)) {
								serverIps.Add(serverName);
							}
						}
						else if (nvp.StartsWith("DNS Name=", StringComparison.Ordinal)) {
							var serverName = nvp.Substring(9);
							if (!serverIps.Contains(serverName)) {
								serverNames.Add(serverName);
							}
						}
					}
				}

				int end = proxy.Target.IndexOf("/", 8);
				string proxyHost = end > 0 ? proxy.Target.Substring(8, end - 8) : proxy.Target.Substring(8);
				if (!serverIps.Contains(proxyHost) && !(!string.IsNullOrEmpty(proxy.OverrideHost) && serverNames.Contains(proxy.OverrideHost))) {
					_logger.LogWarning(string.Format("Failed to validate certificate '{0}'. expected: {1}" + (string.IsNullOrEmpty(proxy.OverrideHost) ? string.Empty : " or {2}") + ", serverIps: [{3}], serverNames: [{4}]", certificate.Subject, proxyHost, proxy.OverrideHost, string.Join(", ", serverIps), string.Join(", ", serverNames)));
					return false;
				}

				LogValidCertificate(certificate, chain);
				return true;
			}
			// regular certificate validation
			if (sslPolicyErrors != SslPolicyErrors.None) {
				LogInvalidCertificate(certificate, sslPolicyErrors, chain);
				return false;
			}
			LogValidCertificate(certificate, chain);
			return true;
		}

		private static HttpMethod GetHttpMethod(string method, out bool? hasBody) {
			if (HttpMethods.IsDelete(method)) { hasBody = null; return HttpMethod.Delete; }
			else if (HttpMethods.IsGet(method)) { hasBody = false; return HttpMethod.Get; }
			else if (HttpMethods.IsHead(method)) { hasBody = false; return HttpMethod.Head; }
			else if (HttpMethods.IsOptions(method)) { hasBody = null; return HttpMethod.Options; }
			else if (HttpMethods.IsPost(method)) { hasBody = true; return HttpMethod.Post; }
			else if (HttpMethods.IsPut(method)) { hasBody = true; return HttpMethod.Put; }
			else if (HttpMethods.IsPatch(method)) { hasBody = true; return HttpMethod.Patch; }
			else if (HttpMethods.IsTrace(method)) { hasBody = null; return HttpMethod.Trace; }
			hasBody = null;
			return new HttpMethod(method);
		}

		private async Task Proxy(IProxyConfiguration proxy, HttpContext context) {
			var id = Guid.NewGuid().ToString("D");
			string path = context.Request.Path + context.Request.QueryString;
			//_logger.LogInformation($"{id} start {context.Request.Method} {path}");

			path = CommonUtility.CombineWithSlash(proxy.Target, path.Substring(proxy.Path.Length));

			if (context.WebSockets.IsWebSocketRequest) {
				await HandleWebSocket(id, proxy, path, context);
				return;
			}

			HttpRequestMessage request = new HttpRequestMessage(GetHttpMethod(context.Request.Method, out var hasBody), path);
			//request.Version = HttpVersion.Version11;

			if (!hasBody.HasValue) {
				hasBody = context.Request.Headers.ContainsKey("Transfer-Encoding") || context.Request.Headers.ContainsKey("Content-Length");
			}
			HttpContent content = null;
			if (hasBody.Value) {
				content = new StreamContent(context.Request.Body);
				request.Content = content;
			}

			if (proxy.Headers != null) {
				foreach (var kv in proxy.Headers) {
					bool success;
					if (kv.Key.StartsWith("Content-", StringComparison.Ordinal)) {
						success = content?.Headers.TryAddWithoutValidation(kv.Key, kv.Value) ?? false;
					}
					else {
						success = request.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
					}
					if (!success) {
						_logger.LogWarning($"Failed to add header {kv.Key}: {kv.Value}.");
					}
				}
			}

			foreach (var kv in context.Request.Headers) {
				if (proxy.RemoveHeaders != null) {
					if (proxy.RemoveHeaders.Contains(kv.Key)) {
						continue;
					}
				}
				// strip 'Transfer-Encoding: chunked' the whole request is send, we are not a transport level proxy
				if (string.Equals("Transfer-Encoding", kv.Key, StringComparison.Ordinal) ||
						string.Equals("Expect", kv.Key, StringComparison.Ordinal) ||
						string.Equals("Host", kv.Key, StringComparison.Ordinal))
				//string.Equals("Connection", kv.Key, StringComparison.Ordinal))
				{
					_logger.LogDebug($"Stripping request {kv.Key}: {kv.Value}");
					continue;
				}

				bool success;
				// Content-Length, Content-Type
				if (kv.Key.StartsWith("Content-", StringComparison.Ordinal)) {
					success = content?.Headers.TryAddWithoutValidation(kv.Key, (IEnumerable<string>)kv.Value) ?? false;
				}
				else {
					success = request.Headers.TryAddWithoutValidation(kv.Key, (IEnumerable<string>)kv.Value);
				}
				if (!success && !kv.Key.StartsWith(":", StringComparison.Ordinal)) {
					_logger.LogWarning($"Failed to add header {kv.Key}: {kv.Value}.");
				}
			}

			var client = GetHttpClient(proxy);
			try {
				Task<HttpResponseMessage> responseTask = client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
				HttpResponseMessage response = null;
				try {
					response = await responseTask.ConfigureAwait(false);
				}
				catch (Exception ex) {
					_logger.LogInformation($"{id} failed {context.Request.Method} {path} - {ex.Message}");
					throw;
				}

				using (response) {
					context.Response.StatusCode = (int)response.StatusCode;

					foreach (var header in response.Headers) {
						// strip 'Transfer-Encoding: chunked' the whole response is read, we are not a transport level proxy
						if (string.Equals("Transfer-Encoding", header.Key, StringComparison.Ordinal) ||
								string.Equals("Expect", header.Key, StringComparison.Ordinal) ||
								string.Equals("Host", header.Key, StringComparison.Ordinal))
						//string.Equals("Connection", header.Key, StringComparison.Ordinal))
						{
							_logger.LogDebug($"Stripping response {header.Key}: {string.Join(", ", header.Value)}");
							continue;
						}
						context.Response.Headers[header.Key] = header.Value.ToArray();
					}

					foreach (var header in response.Content.Headers) {
						context.Response.Headers[header.Key] = header.Value.ToArray();
					}

					using (var stream = await response.Content.ReadAsStreamAsync()) {
						await stream.CopyToAsync(context.Response.Body);
					}

					//_logger.LogInformation($"{id} done {(int)response.StatusCode} {context.Request.Method} {path}");
				}
			}
			finally {
				if (proxy.NewHttpClient) {
					client.Dispose();
				}
			}
		}

		private async Task HandleWebSocket(string id, IProxyConfiguration proxy, string path, HttpContext context) {
			using (var localSocket = await context.WebSockets.AcceptWebSocketAsync()) {
				_logger.LogInformation($"{id} accepted websocket connection {proxy.Path}");

				using (var remoteSocket = new ClientWebSocket()) {
					foreach (var kv in context.Request.Headers) {
						if (proxy.RemoveHeaders != null) {
							if (proxy.RemoveHeaders.Contains(kv.Key)) {
								continue;
							}
						}
						// strip 'Transfer-Encoding: chunked' the whole request is send, we are not a transport level proxy
						if (string.Equals("Transfer-Encoding", kv.Key, StringComparison.Ordinal) ||
										string.Equals("Expect", kv.Key, StringComparison.Ordinal) ||
										string.Equals("Host", kv.Key, StringComparison.Ordinal) ||
										string.Equals("Connection", kv.Key, StringComparison.Ordinal) ||
										string.Equals("Upgrade", kv.Key, StringComparison.Ordinal) ||
										kv.Key.StartsWith("Sec-WebSocket-", StringComparison.Ordinal)) {
							_logger.LogDebug($"Stripping request {kv.Key}: {kv.Value}");
							continue;
						}

						remoteSocket.Options.SetRequestHeader(kv.Key, kv.Value);
					}

					if (path.StartsWith("https://", StringComparison.Ordinal)) {
						await remoteSocket.ConnectAsync(new Uri("wss" + path.Substring(5), UriKind.Absolute), CancellationToken.None);
					}
					else if (path.StartsWith("http://", StringComparison.Ordinal)) {
						await remoteSocket.ConnectAsync(new Uri("ws" + path.Substring(4), UriKind.Absolute), CancellationToken.None);
					}
					else {
						throw new NotSupportedException(proxy.Target);
					}

					_logger.LogInformation($"{id} connected to remote websocket {path}");

					var buffer1 = new byte[1024];
					var buffer2 = new byte[1024];

					var task1 = localSocket.ReceiveAsync(buffer1, context.RequestAborted);
					var task2 = remoteSocket.ReceiveAsync(buffer2, context.RequestAborted);

					while (true) {
						var completed = await Task.WhenAny(task1, task2);
						if (completed.Status != TaskStatus.RanToCompletion) {
							_logger.LogInformation(completed.Exception, $"{id} websocket did not complete {path}");
							return;
						}

						WebSocket socket1;
						WebSocket socket2;
						byte[] buffer;

						if (completed == task1) {
							socket1 = localSocket;
							socket2 = remoteSocket;
							buffer = buffer1;
						}
						else if (completed == task2) {
							socket1 = remoteSocket;
							socket2 = localSocket;
							buffer = buffer2;
						}
						else {
							throw new InvalidOperationException("WhenAny unknown task");
						}

						var close = false;
						var message = completed.Result;
						while (true) {
							if (message.MessageType == WebSocketMessageType.Close) {
								close = true;
							}

							await socket2.SendAsync(new ArraySegment<byte>(buffer, 0, message.Count),
									message.MessageType,
									message.EndOfMessage,
									context.RequestAborted);

							if (message.EndOfMessage) {
								break;
							}

							message = await socket1.ReceiveAsync(buffer, context.RequestAborted);
						}

						if (close) {
							await socket2.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, message.CloseStatusDescription, context.RequestAborted);
							return;
						}

						var newTask = socket1.ReceiveAsync(buffer, context.RequestAborted);
						if (completed == task1) {
							task1 = newTask;
						}
						else if (completed == task2) {
							task1 = newTask;
						}
					}
				}
			}
		}
	}
}
