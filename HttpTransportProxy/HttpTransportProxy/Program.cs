using HttpTransportProxy.Config;
using HttpTransportProxy.PlatformSpecific;
using HttpTransportProxy.Utilities;
using Microsoft.Extensions.Configuration;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace HttpTransportProxy {
	class Program {

		private static bool _isWindows;
		private static IFarmSettings _settings;

		static async Task Main(string[] args) {
			IConfiguration config = GetConfiguration();
			_isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
			_settings = await GetFarSettings(config);

			Func<Task> acceptAction = Accept;
			_ = Task.Run(acceptAction);

			do {
				string line = Console.ReadLine();
				if (string.Equals("exit", line, StringComparison.Ordinal)) {
					break;
				}
			}
			while (true);

			LogInformation("Completed");
		}

		private static async Task Accept() {
			var ipAddress = IPAddress.Any;
			var sockets = new List<(Socket socket, X509Certificate2 certificate)>();
			var tasks = new List<Task<Socket>>();

			var serverBindings = _settings.ServerBindings;
			if (serverBindings != null) {
				foreach (var kv in serverBindings) {
					var certificate = GetServerCertificate(kv.Config);
					if (certificate == null) {
						// non-secure binding
						var listenSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
						listenSocket.Bind(new IPEndPoint(ipAddress, kv.Port));
						LogInformation($"Listening on port {kv.Port}");
						listenSocket.Listen(120);
						sockets.Add((listenSocket, null));
						tasks.Add(listenSocket.AcceptAsync());
					}
					else {
						// secure binding
						var listenSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
						listenSocket.Bind(new IPEndPoint(ipAddress, kv.Port));
						LogInformation($"Listening on port {kv.Port}");
						listenSocket.Listen(120);
						sockets.Add((listenSocket, certificate));
						tasks.Add(listenSocket.AcceptAsync());
					}
				}
			}

			while (true) {
				await Task.WhenAny(tasks);
				for (var i = tasks.Count - 1; i >= 0; i--) {
					var t = tasks[i];
					if (t.IsCompletedSuccessfully) {
						var socket = sockets[i];
						tasks[i] = socket.socket.AcceptAsync();
						Func<Task> acceptAction = () => HandleConnection(t.Result, socket.certificate);
						_ = Task.Run(acceptAction);
					}
					else if (t.IsCompleted) {
						// throw
						await t;
					}
				}
			}
		}

		private static async Task HandleConnection(Socket socket, X509Certificate2 certificate) {
			try {
				await HandleConnectionInternal(socket, certificate);
			}
			catch (Exception ex) {
				LogWarning("Exception: " + ex.Message);
			}
		}

		private static async Task HandleConnectionInternal(Socket socket, X509Certificate2 certificate) {
			LogInformation($"Accepted connection from {socket.RemoteEndPoint}");

			List<string> requestHeaders = new List<string>(10);
			List<string> responseHeaders = new List<string>(10);
			long requestContentLength = 0, responseContentLength = 0;
			ReadState requestState = new ReadState();
			ReadState responseState = new ReadState();
			Dictionary<string, (Socket socket, NetworkStream stream, SslStream sslStream)> serverConnections = new Dictionary<string, (Socket socket, NetworkStream stream, SslStream sslStream)>(StringComparer.Ordinal);
			SslStream sourceSslStream = null;
			try {
				await using (var clientStream = new NetworkStream(socket, FileAccess.ReadWrite, false)) {
					Stream sourceStream = clientStream;
					if (certificate != null) {
						sourceStream = sourceSslStream = new SslStream(clientStream, true);
						var protocols = SslProtocols.Tls12;
						if (!_isWindows) {
							protocols |= SslProtocols.Tls13;
						}
						//CipherSuitesPolicy policy = new CipherSuitesPolicy(new[] {
						//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						//	TlsCipherSuite.TLS_AES_128_GCM_SHA256,
						//	TlsCipherSuite.TLS_AES_256_GCM_SHA384,
						//	TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
						//});
						await sourceSslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions() {
							ApplicationProtocols = new List<SslApplicationProtocol>() {
							SslApplicationProtocol.Http11,
							//SslApplicationProtocol.Http2
						},
							ClientCertificateRequired = false,
							EnabledSslProtocols = protocols,
							ServerCertificate = certificate,
							AllowRenegotiation = false,
							CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
							EncryptionPolicy = EncryptionPolicy.RequireEncryption,
						});
					}

					requestState.buffer = ArrayPool<byte>.Shared.Rent(1024);
					requestState.bytesBuffered = 0;
					requestState.bytesConsumed = 0;
					requestState.bytesIndex = 0;

					responseState.buffer = ArrayPool<byte>.Shared.Rent(1024);
					responseState.bytesBuffered = 0;
					responseState.bytesConsumed = 0;
					responseState.bytesIndex = 0;

				start:

					var status = await ReadHeaderData(sourceStream, requestState, requestHeaders);
					if (status != ReadDataStatus.Completed) {
						LogRequestStatus(status);
						return;
					}

					int i = requestHeaders[0].IndexOf(' ');
					if (i < 0) {
						LogWarning("Unexpected request from client");
						return;
					}

					string verb = requestHeaders[0].Substring(0, i);
					int i2 = requestHeaders[0].IndexOf(' ', i + 1);
					if (i2 < 0) {
						LogWarning("Unexpected request from client");
						return;
					}

					string destination = requestHeaders[0].Substring(i + 1, i2 - i - 1);

					// select proxy
					IProxyConfiguration proxy = null;
					foreach (var s in _settings.Proxy) {
						if (destination.StartsWith(s.Path, StringComparison.OrdinalIgnoreCase) && (s.Path.Length == destination.Length || destination[s.Path.Length] == '/')) {
							proxy = s;
							break;
						}
					}

					if (proxy == null) {
						LogWarning($"No proxy configuration for request to {destination}");
						return;
					}

					var path = CommonUtility.CombineWithSlash("/", destination.Substring(proxy.Path.Length));
					requestHeaders[0] = verb + " " + path + requestHeaders[0].Substring(i2);

					var targetUri = new Uri(proxy.Target, UriKind.Absolute);
					bool isContinue, keepAlive, isRequestChunked;
					string originalHost;
					// process request headers
					if (!ProcessRequestHeaders(requestHeaders, targetUri, out originalHost, out isContinue, out keepAlive, out isRequestChunked, out requestContentLength)) {
						return;
					}

					if (!serverConnections.TryGetValue(proxy.Target, out var serverConnection)) {
						IPAddress[] serverIps = Dns.GetHostAddresses(targetUri.DnsSafeHost);
						if (serverIps == null || serverIps.Length == 0) {
							LogWarning($"Failed to resolve addresses of {proxy.Target}");
							return;
						}
						int connectPort = targetUri.Port;
						var remoteSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
						await remoteSocket.ConnectAsync(serverIps, connectPort);

						SslStream targetSslStream = null;
						var remoteStream = new NetworkStream(remoteSocket, FileAccess.ReadWrite, false);
						if (targetUri.Scheme == Uri.UriSchemeHttps) {
							var protocols = SslProtocols.Tls12;
							if (!_isWindows) {
								protocols |= SslProtocols.Tls13;
							}
							//CipherSuitesPolicy policy = new CipherSuitesPolicy(new[] {
							//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
							//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
							//	TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
							//	TlsCipherSuite.TLS_AES_128_GCM_SHA256,
							//	TlsCipherSuite.TLS_AES_256_GCM_SHA384,
							//	TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
							//});
							await targetSslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions() {
								AllowRenegotiation = false,
								ApplicationProtocols = new List<SslApplicationProtocol>() {
									SslApplicationProtocol.Http11,
									//SslApplicationProtocol.Http2
								},
								CertificateRevocationCheckMode = X509RevocationMode.Online,
								//CipherSuitesPolicy = policy,
								EnabledSslProtocols = protocols,
								EncryptionPolicy = EncryptionPolicy.RequireEncryption,
								TargetHost = targetUri.Host,
								RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => ValidateServerCertificate(certificate, chain, sslPolicyErrors, proxy)
							});
						}
						serverConnection = (remoteSocket, remoteStream, targetSslStream);
						serverConnections.Add(proxy.Target, serverConnection);
					}

					Stream targetStream = serverConnection.stream;
					if (serverConnection.sslStream != null) {
						targetStream = serverConnection.sslStream;
					}
					if (isContinue) {
						await WriteHeaders(requestHeaders, targetStream);

						status = await ReadHeaderData(targetStream, responseState, responseHeaders);
						if (status != ReadDataStatus.Completed) {
							LogResponseStatus(status);
							return;
						}

						bool isServerContinue = false;
						if (string.Equals(responseHeaders[0], "HTTP/1.1 100 Continue", StringComparison.Ordinal)) {
							isServerContinue = true;
						}
						//else if (string.Equals(responseHeaders[0], "HTTP/1.1 417 Expectation Failed", StringComparison.Ordinal)) {
						//	isServerContinue = false;
						//}

						bool isResponseChunked;
						if (isServerContinue) {
							await WriteHeaders(responseHeaders, sourceStream);

							var status2 = await ReadBodyData(sourceStream, targetStream, requestState, isRequestChunked, requestContentLength);
							if (status2.status != ReadDataStatus.Completed) {
								LogRequestStatus(status2, requestState, requestContentLength);
								return;
							}

							responseHeaders.Clear();
							status = await ReadHeaderData(targetStream, responseState, responseHeaders);
							if (status != ReadDataStatus.Completed) {
								LogResponseStatus(status);
								return;
							}

							if (!ProcessResponseHeaders(responseHeaders, certificate != null, originalHost, out isResponseChunked, out responseContentLength)) {
								return;
							}

							await WriteHeaders(responseHeaders, sourceStream);
						}
						else {
							if (!ProcessResponseHeaders(responseHeaders, certificate != null, originalHost, out isResponseChunked, out responseContentLength)) {
								return;
							}

							await WriteHeaders(responseHeaders, sourceStream);
						}

						var status3 = await ReadBodyData(targetStream, sourceStream, responseState, isResponseChunked, responseContentLength);
						if (status3.status != ReadDataStatus.Completed) {
							LogResponseStatus(status3, requestState, requestContentLength);
							return;
						}
					}
					else {
						await WriteHeaders(requestHeaders, targetStream);

						var status2 = await ReadBodyData(sourceStream, targetStream, requestState, isRequestChunked, requestContentLength);
						if (status2.status != ReadDataStatus.Completed) {
							LogRequestStatus(status2, requestState, requestContentLength);
							return;
						}

						status = await ReadHeaderData(targetStream, responseState, responseHeaders);
						if (status != ReadDataStatus.Completed) {
							LogResponseStatus(status);
							return;
						}

						if (!ProcessResponseHeaders(responseHeaders, certificate != null, originalHost, out var isResponseChunked, out responseContentLength)) {
							return;
						}

						await WriteHeaders(responseHeaders, sourceStream);

						status2 = await ReadBodyData(targetStream, sourceStream, responseState, isResponseChunked, responseContentLength);
						if (status2.status != ReadDataStatus.Completed) {
							LogResponseStatus(status2, requestState, requestContentLength);
							return;
						}
					}

					if (keepAlive) {
						requestState.bodyLength = 0;
						responseState.bodyLength = 0;
						requestHeaders.Clear();
						responseHeaders.Clear();
						goto start;
					}

					socket.Shutdown(SocketShutdown.Both);

					LogInformation("Request completed");
				}
			}
			finally {

				if (sourceSslStream != null) {
					await sourceSslStream.DisposeAsync();
				}

				foreach (var kv in serverConnections) {
					kv.Value.socket.Shutdown(SocketShutdown.Both);
					await kv.Value.stream.DisposeAsync();
					if (kv.Value.sslStream != null) {
						await kv.Value.sslStream.DisposeAsync();
					}
				}

				if (responseState.buffer != null) {
					ArrayPool<byte>.Shared.Return(responseState.buffer);
				}
				if (requestState.buffer != null) {
					ArrayPool<byte>.Shared.Return(requestState.buffer);
				}
				socket.Dispose();
			}
		}

		private static bool ProcessRequestHeaders(List<string> requestHeaders, Uri targetUri, out string originalHost, out bool isContinue, out bool keepAlive, out bool isRequestChunked, out long requestContentLength) {
			originalHost = null;
			requestContentLength = 0;
			isContinue = keepAlive = isRequestChunked = false;
			for (int i = 0; i < requestHeaders.Count; i++) {
				var line = requestHeaders[i];
				if (string.Equals("Expect: 100-continue", line, StringComparison.Ordinal)) {
					isContinue = true;
				}
				else if (line.StartsWith("Content-Length: ", StringComparison.Ordinal)) {
					if (!long.TryParse(line.Substring("Content-Length: ".Length), NumberStyles.None, CultureInfo.InvariantCulture, out requestContentLength)) {
						LogWarning($"Failed to parse content length '{line}'");
						return false;
					}
				}
				else if (string.Equals("Transfer-Encoding: chunked", line, StringComparison.OrdinalIgnoreCase)) {
					isRequestChunked = true;
				}
				else if (line.StartsWith("Host: ", StringComparison.Ordinal)) {
					originalHost = line.Substring(6);
					requestHeaders[i] = "Host: " + targetUri.Host + (targetUri.IsDefaultPort ? string.Empty : ":" + targetUri.Port.ToString(CultureInfo.InvariantCulture));
				}
				else if (string.Equals("Connection: keep-alive", line, StringComparison.Ordinal)) {
					keepAlive = true;
				}
			}
			return true;
		}

		private static bool ProcessResponseHeaders(List<string> responseHeaders, bool isHttps, string originalHost, out bool isResponseChunked, out long responseContentLength) {
			responseContentLength = 0;
			isResponseChunked = false;
			for (int i = 0; i < responseHeaders.Count; i++) {
				var line = responseHeaders[i];
				if (line.StartsWith("Content-Length: ", StringComparison.Ordinal)) {
					if (!long.TryParse(line.Substring("Content-Length: ".Length), NumberStyles.None, CultureInfo.InvariantCulture, out responseContentLength)) {
						LogWarning($"Failed to parse content length '{line}'");
						return false;
					}
				}
				else if (string.Equals("Transfer-Encoding: chunked", line, StringComparison.OrdinalIgnoreCase)) {
					isResponseChunked = true;
				}
				// rewrite redirects
				else if (line.StartsWith("Location: ", StringComparison.Ordinal)) {
					var target = line.Substring(10).TrimEnd('/');
					IProxyConfiguration proxy2 = null;
					foreach (var s in _settings.Proxy) {
						if (target.StartsWith(s.Target, StringComparison.OrdinalIgnoreCase) && (s.Target.Length == target.Length || target[s.Target.Length] == '/')) {
							proxy2 = s;
							break;
						}
					}
					if (proxy2 != null) {
						responseHeaders[i] = "Location: " + CommonUtility.CombineWithSlash((isHttps ? Uri.UriSchemeHttps : Uri.UriSchemeHttp) + "://" + originalHost, proxy2.Path, target.Substring(proxy2.Target.Length));
					}
				}
			}
			return true;
		}

		private sealed class ReadState {
			public int bytesBuffered;
			public int bytesConsumed;
			public int bytesIndex;
			public byte[] buffer;
			public long bodyLength;
		}

		private enum ReadDataStatus {
			Completed,
			ConnectionClosed,
			UnexpectedData,
			InvalidChunkSize,
			InvalidChunkEnd,
			MoreDataExpected,
			MoreDataReceivedThanExpected,
			UnexpectedBodyLength
		}

		private static async Task<ReadDataStatus> ReadHeaderData(Stream stream, ReadState readState, List<string> headers) {
			bool isEnd = false;
			while (!isEnd /*&& stream.DataAvailable*/) {
				var bytesInBuffer = readState.bytesBuffered - readState.bytesConsumed;
				if (bytesInBuffer > (readState.buffer.Length / 2)) {
					// expand buffer
					var newBuffer = ArrayPool<byte>.Shared.Rent((readState.buffer.Length < (int.MaxValue / 2)) ? readState.buffer.Length * 2 : int.MaxValue);
					// copy the unprocessed data
					Buffer.BlockCopy(readState.buffer, readState.bytesConsumed, newBuffer, 0, bytesInBuffer);
					ArrayPool<byte>.Shared.Return(readState.buffer);
					readState.buffer = newBuffer;
				}
				else if (bytesInBuffer > 0) {
					Buffer.BlockCopy(readState.buffer, readState.bytesConsumed, readState.buffer, 0, bytesInBuffer);
				}
				readState.bytesIndex -= readState.bytesConsumed;
				readState.bytesConsumed = 0;

				var bytesRead = await stream.ReadAsync(readState.buffer, bytesInBuffer, readState.buffer.Length - bytesInBuffer);
				if (bytesRead == 0) {
					return ReadDataStatus.ConnectionClosed;
				}

				readState.bytesBuffered = bytesInBuffer + bytesRead;

				// look for CRLF | RFC 2616
				int linePosition;
				do {
					linePosition = Array.IndexOf(readState.buffer, (byte)'\n', readState.bytesIndex, readState.bytesBuffered - readState.bytesIndex);
					if (linePosition >= 0) {
						if (linePosition == 0 || readState.buffer[linePosition - 1] != (byte)'\r') {
							readState.bytesIndex = linePosition + 1;
						}
						else {
							var count = linePosition - readState.bytesConsumed - 1;
							if (count > 0) {
								var line = Encoding.UTF8.GetString(readState.buffer, readState.bytesConsumed, count);
								headers.Add(line);
								readState.bytesConsumed = linePosition + 1;
							}
							else {
								readState.bytesConsumed = linePosition + 1;
								readState.bytesIndex = readState.bytesConsumed;
								isEnd = true;
								break;
							}
							readState.bytesIndex = linePosition + 1;
						}
					}
				}
				while (linePosition >= 0);
			}

			if (headers.Count == 0 || !isEnd) {
				return ReadDataStatus.UnexpectedData;
			}

			return ReadDataStatus.Completed;
		}

		private static async Task<(ReadDataStatus status, string data)> ReadBodyData(Stream sourceStream, Stream targetStream, ReadState readState, bool isChunked, long contentLength) {
			bool isEnd = false;
			if (isChunked) {
				// write remaining data
				var bytesInBuffer = readState.bytesBuffered - readState.bytesConsumed;
				if (bytesInBuffer > 0) {
					readState.bodyLength += bytesInBuffer;
					await targetStream.WriteAsync(readState.buffer, readState.bytesConsumed, bytesInBuffer);
				}

				int chunkCount = 0;
				long chunkSize = 0, chunkLength = 0;
				bool isStart = true, getMoreData;
				readState.bytesIndex = readState.bytesConsumed;
				do {
					if (isStart) {
						getMoreData = true;
						// look for CRLF
						int linePosition;
						do {
							linePosition = Array.IndexOf(readState.buffer, (byte)'\n', readState.bytesIndex, readState.bytesBuffered - readState.bytesIndex);
							if (linePosition >= 0) {
								if (linePosition == 0 || readState.buffer[linePosition - 1] != (byte)'\r') {
									readState.bytesIndex = linePosition + 1;
								}
								else {
									var line = Encoding.UTF8.GetString(readState.buffer, readState.bytesConsumed, linePosition - readState.bytesConsumed - 1);
									readState.bytesConsumed = linePosition + 1;
									readState.bytesIndex = readState.bytesConsumed;
									isStart = false;
									if (line.Length == 0 || !long.TryParse(line, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out chunkSize) || chunkSize < 0) {
										return (ReadDataStatus.InvalidChunkSize, line);
									}
									getMoreData = false;
									break;
								}
							}
						}
						while (linePosition >= 0);
					}
					else if (isEnd) {
						getMoreData = true;
						bytesInBuffer = readState.bytesBuffered - readState.bytesConsumed;
						if (bytesInBuffer > 1) {
							if (readState.buffer[readState.bytesConsumed] != (byte)'\r' || readState.buffer[readState.bytesConsumed + 1] != (byte)'\n') {
								return (ReadDataStatus.InvalidChunkEnd, $"{readState.buffer[readState.bytesConsumed]:x2}{readState.buffer[readState.bytesConsumed + 1]:x2}");
							}
							chunkCount++;
							if (chunkSize == 0) {
								readState.bytesConsumed += 2;
								readState.bytesIndex = readState.bytesConsumed;
								getMoreData = false;
								break;
							}
							isEnd = false;
							isStart = true;
							readState.bytesConsumed += 2;
							readState.bytesIndex = readState.bytesConsumed;
							readState.bodyLength += chunkSize;
							chunkLength = 0;
							chunkSize = 0;
							getMoreData = false;
						}
					}
					else {
						var remaining = chunkSize - chunkLength;
						var nextBlock = readState.bytesBuffered - readState.bytesConsumed;
						if (nextBlock > remaining) {
							nextBlock = (int)remaining;
						}
						readState.bytesConsumed += nextBlock;
						readState.bytesIndex = readState.bytesConsumed;
						chunkLength += nextBlock;
						isEnd = chunkLength == chunkSize;
						getMoreData = !isEnd;
					}

					if (getMoreData) {
						bytesInBuffer = readState.bytesBuffered - readState.bytesConsumed;
						if (bytesInBuffer > (readState.buffer.Length / 2)) {
							// expand buffer
							var newBuffer = ArrayPool<byte>.Shared.Rent((readState.buffer.Length < (int.MaxValue / 2)) ? readState.buffer.Length * 2 : int.MaxValue);
							// copy the unprocessed data
							Buffer.BlockCopy(readState.buffer, readState.bytesConsumed, newBuffer, 0, bytesInBuffer);
							ArrayPool<byte>.Shared.Return(readState.buffer);
							readState.buffer = newBuffer;
						}
						else if (bytesInBuffer > 0) {
							Buffer.BlockCopy(readState.buffer, readState.bytesConsumed, readState.buffer, 0, bytesInBuffer);
						}
						readState.bytesIndex -= readState.bytesConsumed;
						readState.bytesConsumed = 0;

						var bytesRead = await sourceStream.ReadAsync(readState.buffer, bytesInBuffer, readState.buffer.Length - bytesInBuffer);
						if (bytesRead == 0) {
							return (ReadDataStatus.ConnectionClosed, null);
						}
						readState.bytesBuffered = bytesInBuffer + bytesRead;
						await targetStream.WriteAsync(readState.buffer, bytesInBuffer, bytesRead);
					}
				}
				while (true);

				if (!isEnd || getMoreData) {
					return (ReadDataStatus.MoreDataExpected, null);
				}

				bytesInBuffer = readState.bytesBuffered - readState.bytesConsumed;
				if (bytesInBuffer > 0) {
					return (ReadDataStatus.MoreDataReceivedThanExpected, null);
				}
			}
			else {
				// write remaining data
				var bytesInBuffer = readState.bytesBuffered - readState.bytesConsumed;
				if (bytesInBuffer > 0) {
					readState.bodyLength += bytesInBuffer;
					await targetStream.WriteAsync(readState.buffer, readState.bytesConsumed, bytesInBuffer);
					readState.bytesConsumed += bytesInBuffer;
					readState.bytesIndex = readState.bytesConsumed;
				}

				// read remaining data
				while (readState.bodyLength < contentLength) {
					var bytesRead = await sourceStream.ReadAsync(readState.buffer);
					if (bytesRead == 0) {
						break;
					}

					readState.bodyLength += bytesRead;
					await targetStream.WriteAsync(readState.buffer, 0, bytesRead);
				}

				if (readState.bodyLength != contentLength) {
					return (ReadDataStatus.UnexpectedBodyLength, null);
				}
			}
			return (ReadDataStatus.Completed, null);
		}

		private static async Task WriteHeaders(List<string> headers, Stream stream) {
			var buffer = ArrayPool<byte>.Shared.Rent(1024);
			try {
				foreach (var header in headers) {
					var b = Encoding.UTF8.GetByteCount(header) + 2;
					if (b > buffer.Length) {
						ArrayPool<byte>.Shared.Return(buffer);
						buffer = ArrayPool<byte>.Shared.Rent(b);
					}
					int l = Encoding.UTF8.GetBytes(header, buffer);
					buffer[l] = (byte)'\r';
					buffer[l + 1] = (byte)'\n';
					await stream.WriteAsync(buffer, 0, l + 2);
				}
				buffer[0] = (byte)'\r';
				buffer[1] = (byte)'\n';
				await stream.WriteAsync(buffer, 0, 2);
			}
			finally {
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}

		private static void LogRequestStatus(ReadDataStatus status) {
			if (status == ReadDataStatus.ConnectionClosed) {
				LogWarning("Client closed the connection");
			}
			else if (status == ReadDataStatus.UnexpectedData) {
				LogWarning("Unexpected data received from client");
			}
			else {
				throw new NotImplementedException(status.ToString());
			}
		}

		private static void LogRequestStatus((ReadDataStatus status, string data) status, ReadState readState, long contentLength) {
			if (status.status == ReadDataStatus.ConnectionClosed) {
				LogWarning("Client closed the connection");
			}
			else if (status.status == ReadDataStatus.InvalidChunkSize) {
				LogWarning($"Unexpected chunk size '{status.data}' received from client");
			}
			else if (status.status == ReadDataStatus.InvalidChunkEnd) {
				LogWarning($"Unexpected chunk end '{status.data}' received from client");
			}
			else if (status.status == ReadDataStatus.MoreDataExpected) {
				LogWarning($"Expected more data from client");
			}
			else if (status.status == ReadDataStatus.MoreDataReceivedThanExpected) {
				LogWarning($"More data received from client than expected");
			}
			else if (status.status == ReadDataStatus.UnexpectedBodyLength) {
				LogWarning($"Unexpected request length {readState.bodyLength} expected {contentLength}");
			}
			else {
				throw new NotImplementedException(status.ToString());
			}
		}

		private static void LogResponseStatus(ReadDataStatus status) {
			if (status == ReadDataStatus.ConnectionClosed) {
				LogWarning("Server closed the connection");
			}
			else if (status == ReadDataStatus.UnexpectedData) {
				LogWarning("Unexpected data received from server");
			}
			else {
				throw new NotImplementedException(status.ToString());
			}
		}

		private static void LogResponseStatus((ReadDataStatus status, string data) status, ReadState readState, long contentLength) {
			if (status.status == ReadDataStatus.ConnectionClosed) {
				LogWarning("Server closed the connection");
			}
			else if (status.status == ReadDataStatus.InvalidChunkSize) {
				LogWarning($"Unexpected chunk size '{status.data}' received from server");
			}
			else if (status.status == ReadDataStatus.InvalidChunkEnd) {
				LogWarning($"Unexpected chunk end '{status.data}' received from server");
			}
			else if (status.status == ReadDataStatus.MoreDataExpected) {
				LogWarning($"Expected more data from server");
			}
			else if (status.status == ReadDataStatus.MoreDataReceivedThanExpected) {
				LogWarning($"More data received from server than expected");
			}
			else if (status.status == ReadDataStatus.UnexpectedBodyLength) {
				LogWarning($"Unexpected response length {readState.bodyLength} expected {contentLength}");
			}
			else {
				throw new NotImplementedException(status.ToString());
			}
		}

		private static async Task<IFarmSettings> GetFarSettings(IConfiguration config) {
			var appSettings = new FarmSettingsValues();
			config.GetSection("FarmSettings").Bind(appSettings);

			string json;
			await using (var file = File.Open(appSettings.ConfigPath + "\\HttpProxy.global.js", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
				using (var sr = new StreamReader(file, Encoding.UTF8, false)) {
					json = await sr.ReadToEndAsync();
				}
			}

			var global = JsonSerializer.Deserialize<GlobalConfig>(json, new JsonSerializerOptions() {
				PropertyNameCaseInsensitive = false,
				AllowTrailingCommas = false,
				ReadCommentHandling = JsonCommentHandling.Skip
			});

			global.Init();
			return global;
		}

		private static IConfiguration GetConfiguration() {
			var builder = new ConfigurationBuilder()
				.SetBasePath(Directory.GetCurrentDirectory())
				.AddJsonFile("appsettings.json");

			IConfiguration config = new ConfigurationBuilder()
				.AddJsonFile("appsettings.json", true, true)
				.Build();
			return config;
		}

		internal enum ServerCertificateProviderType {
			Blob,
			File,
			WindowsStore,
		}

		internal enum ServerCertificatePasswordProviderType {
			None,
			Plain,
		}

		private static X509Certificate2 GetServerCertificate(IServerCertificateSettings serverCertificateSettings) {
			if (serverCertificateSettings == null || string.IsNullOrEmpty(serverCertificateSettings.ServerCertificateProvider)) {
				return null;
			}

			if (!CommonUtility.TryParseEnum<ServerCertificateProviderType>(serverCertificateSettings.ServerCertificateProvider, true, out var serverCertificateProvider)) {
				throw new ApplicationException($"Unsupported ServerCertificateProvider in config: {serverCertificateSettings.ServerCertificateProvider}");
			}

			var serverCertificatePasswordProvider = ServerCertificatePasswordProviderType.None;
			if (!string.IsNullOrEmpty(serverCertificateSettings.ServerCertificatePasswordProvider) && !CommonUtility.TryParseEnum(serverCertificateSettings.ServerCertificatePasswordProvider, true, out serverCertificatePasswordProvider)) {
				throw new ApplicationException($"Unsupported ServerCertificatePasswordProvider in config: {serverCertificateSettings.ServerCertificatePasswordProvider}");
			}

			string password = null;
			if (serverCertificatePasswordProvider == ServerCertificatePasswordProviderType.Plain) {
				password = serverCertificateSettings.ServerCertificatePassword;
			}

			X509Certificate2 certificate = null;
			if (serverCertificateProvider == ServerCertificateProviderType.Blob) {
				byte[] certificateData = Convert.FromBase64String(serverCertificateSettings.ServerCertificate);
				certificate = new X509Certificate2(certificateData, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
			}
			else if (serverCertificateProvider == ServerCertificateProviderType.File) {
				certificate = new X509Certificate2(serverCertificateSettings.ServerCertificate, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
			}
			else if (serverCertificateProvider == ServerCertificateProviderType.WindowsStore && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
				certificate = WindowsCertificateHelper.GetCertificate(StoreName.My, StoreLocation.LocalMachine, serverCertificateSettings.ServerCertificate, DateTime.UtcNow, true, false, out var status);
				if (certificate == null || status != CertificateRetrievalStatus.None) {
					throw new Exception("Certificate '" + serverCertificateSettings.ServerCertificate + "' not found/valid. status: " + status.ToString());
				}
			}
			return certificate;
		}


		private static void LogInvalidCertificate(X509Certificate certificate, SslPolicyErrors sslPolicyErrors, X509Chain chain) {
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

			LogWarning(string.Format("Failed to validate certificate '{0}'. policy: {1}, errorType: {2}\r\nchainErrors:\r\n{3}\r\nchainElements:\r\n{4}", certificate.Subject, policy, sslPolicyErrors.ToString(), chainErrors, chainElements));
		}

		private static void LogInvalidCertificate(X509Certificate certificate, X509Chain chain) {
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

			LogWarning(string.Format("Failed to validate certificate '{0}'. policy: {1}\r\nchainErrors:\r\n{2}\r\nchainElements:\r\n{3}", certificate.Subject, policyInfo, chainErrors, chainElements));
		}

		private static void LogValidCertificate(X509Certificate certificate, X509Chain chain) {
			string policy = string.Empty;
			if (chain != null && chain.ChainPolicy != null) {
				policy = "RevocationMode: " + chain.ChainPolicy.RevocationMode + ", RevocationFlag: " + chain.ChainPolicy.RevocationFlag + ", VerificationFlags: " + chain.ChainPolicy.VerificationFlags;
			}
			LogDebug(string.Format("Successfully validated certificate '{0}'. policy: {1}", certificate.Subject, policy));
		}

		private static bool ValidateServerCertificate(X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors, IProxyConfiguration proxy) {
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
					LogWarning(string.Format("Failed to validate certificate '{0}'. expected: {1}" + (string.IsNullOrEmpty(proxy.OverrideHost) ? string.Empty : " or {2}") + ", serverIps: [{3}], serverNames: [{4}]", certificate.Subject, proxyHost, proxy.OverrideHost, string.Join(", ", serverIps), string.Join(", ", serverNames)));
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

		private static readonly object _syncRoot = new object();
		private static void LogDebug(string message) {
			lock (_syncRoot) {
				var color = Console.ForegroundColor;
				Console.ForegroundColor = ConsoleColor.Gray;
				Console.WriteLine(message);
				Console.ForegroundColor = color;
			}
		}

		private static void LogWarning(string message) {
			lock (_syncRoot) {
				var color = Console.ForegroundColor;
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine(message);
				Console.ForegroundColor = color;
			}
		}

		private static void LogInformation(string message) {
			lock (_syncRoot) {
				var color = Console.ForegroundColor;
				Console.ForegroundColor = ConsoleColor.White;
				Console.WriteLine(message);
				Console.ForegroundColor = color;
			}
		}
	}
}
