using HttpTransportProxy.Config;
using HttpTransportProxy.PlatformSpecific;
using HttpTransportProxy.Utilities;
using Microsoft.Extensions.Configuration;
using System;
using System.Buffers;
using System.Collections.Generic;
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
			_settings = GetFarSettings(config);

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

			byte[] buffer = ArrayPool<byte>.Shared.Rent(1024);
			int bytesBuffered = 0, bytesConsumed = 0, bytesIndex = 0;
			bool unexpectedClose = false, isEnd = false;
			List<string> headers = new List<string>(10);
			long requestLength = 0;
			using (var clientStream = new NetworkStream(socket, FileAccess.ReadWrite, false)) {
				Stream sourceStream = clientStream;
				SslStream sourceSslStream = null;
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

				while (!isEnd /*&& stream.DataAvailable*/) {
					var bytesInBuffer = bytesBuffered - bytesConsumed;
					if (bytesInBuffer > (buffer.Length / 2)) {
						// expand buffer
						var newBuffer = ArrayPool<byte>.Shared.Rent((buffer.Length < (int.MaxValue / 2)) ? buffer.Length * 2 : int.MaxValue);
						// copy the unprocessed data
						Buffer.BlockCopy(buffer, bytesConsumed, newBuffer, 0, bytesInBuffer);
						ArrayPool<byte>.Shared.Return(buffer);
						buffer = newBuffer;
					}
					else if (bytesInBuffer > 0) {
						Buffer.BlockCopy(buffer, bytesConsumed, buffer, 0, bytesInBuffer);
					}
					bytesIndex -= bytesConsumed;
					bytesConsumed = 0;

					var bytesRead = await sourceStream.ReadAsync(buffer, bytesInBuffer, buffer.Length - bytesInBuffer);
					if (bytesRead == 0) {
						LogWarning("Client closed the connection");
						unexpectedClose = true;
						break;
					}

					bytesBuffered = bytesInBuffer + bytesRead;

					// look for CRLF | RFC 2616
					int linePosition;
					do {
						linePosition = Array.IndexOf(buffer, (byte)'\n', bytesIndex, bytesBuffered - bytesIndex);
						if (linePosition >= 0) {
							if (linePosition == 0 || buffer[linePosition - 1] != (byte)'\r') {
								bytesIndex = linePosition + 1;
							}
							else {
								var count = linePosition - bytesConsumed - 1;
								if (count > 0) {
									var line = Encoding.UTF8.GetString(buffer, bytesConsumed, count);
									headers.Add(line);
									bytesConsumed = linePosition + 1;
								}
								else {
									bytesConsumed = linePosition + 1;
									bytesIndex = bytesConsumed;
									isEnd = true;
									break;
								}
								bytesIndex = linePosition + 1;
							}
						}
					}
					while (linePosition >= 0);
				}

				if (unexpectedClose) {
					ArrayPool<byte>.Shared.Return(buffer);
					socket.Close();
					return;
				}

				if (headers.Count == 0 || !isEnd) {
					ArrayPool<byte>.Shared.Return(buffer);
					LogWarning("Unexpected request from client");
					socket.Close();
					return;
				}

				int i = headers[0].IndexOf(' ');
				if (i < 0) {
					ArrayPool<byte>.Shared.Return(buffer);
					LogWarning("Unexpected request from client");
					socket.Close();
					return;
				}

				string verb = headers[0].Substring(0, i);
				int i2 = headers[0].IndexOf(' ', i + 1);
				if (i2 < 0) {
					ArrayPool<byte>.Shared.Return(buffer);
					LogWarning("Unexpected request from client");
					socket.Close();
					return;
				}

				string destination = headers[0].Substring(i + 1, i2 - i - 1);

				// select proxy
				IProxyConfiguration proxy = null;
				foreach (var s in _settings.Proxy) {
					if (destination.StartsWith(s.Path, StringComparison.OrdinalIgnoreCase) && (s.Path.Length == destination.Length || destination[s.Path.Length] == '/')) {
						proxy = s;
						break;
					}
				}

				if (proxy == null) {
					ArrayPool<byte>.Shared.Return(buffer);
					LogWarning($"No proxy configuration for request to {destination}");
					socket.Close();
					return;
				}

				var path = CommonUtility.CombineWithSlash("/", destination.Substring(proxy.Path.Length));
				headers[0] = verb + " " + path + headers[0].Substring(i2);

				var targetUri = new Uri(proxy.Target, UriKind.Absolute);
				bool isContinue = false, isChunked = false;
				long contentLength = 0;
				string originalHost = null;
				for (i = 0; i < headers.Count; i++) {
					var line = headers[i];
					if (string.Equals("Expect: 100-continue", line, StringComparison.Ordinal)) {
						isContinue = true;
					}
					else if (line.StartsWith("Content-Length: ", StringComparison.Ordinal)) {
						if (!long.TryParse(line.Substring("Content-Length: ".Length), NumberStyles.None, CultureInfo.InvariantCulture, out contentLength)) {
							ArrayPool<byte>.Shared.Return(buffer);
							LogWarning($"Failed to parse content length '{line}'");
							socket.Close();
							return;
						}
					}
					else if (string.Equals("Transfer-Encoding: chunked", line, StringComparison.OrdinalIgnoreCase)) {
						isChunked = true;
					}
					else if (line.StartsWith("Host: ", StringComparison.Ordinal)) {
						originalHost = line.Substring(6);
						headers[i] = "Host: " + targetUri.Host + (targetUri.IsDefaultPort ? string.Empty : ":" + targetUri.Port.ToString(CultureInfo.InvariantCulture));
					}
				}

				IPAddress[] serverIps = Dns.GetHostAddresses(targetUri.DnsSafeHost);
				if (serverIps == null || serverIps.Length == 0) {
					ArrayPool<byte>.Shared.Return(buffer);
					LogWarning($"Failed to resolve addresses of {proxy.Target}");
					socket.Close();
					return;
				}
				int connectPort = targetUri.Port;
				using (var remoteSocket = new Socket(SocketType.Stream, ProtocolType.Tcp)) {
					await remoteSocket.ConnectAsync(serverIps, connectPort);

					using (var remoteStream = new NetworkStream(remoteSocket, FileAccess.ReadWrite, false)) {
						Stream targetStream = remoteStream;
						SslStream targetSslStream = null;
						if (targetUri.Scheme == Uri.UriSchemeHttps) {
							targetStream = targetSslStream = new SslStream(remoteStream, true);
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

						List<string> responseHeaders = new List<string>(10);
						long responseLength = 0;
						var buffer2 = ArrayPool<byte>.Shared.Rent(1024);

						// write headers
						foreach (var header in headers) {
							var b = Encoding.UTF8.GetByteCount(header) + 2;
							if (b > buffer2.Length) {
								ArrayPool<byte>.Shared.Return(buffer2);
								buffer2 = ArrayPool<byte>.Shared.Rent(b);
							}
							int l = Encoding.UTF8.GetBytes(header, buffer2);
							buffer2[l] = (byte)'\r';
							buffer2[l + 1] = (byte)'\n';
							await targetStream.WriteAsync(buffer2, 0, l + 2);
						}
						buffer2[0] = (byte)'\r';
						buffer2[1] = (byte)'\n';
						await targetStream.WriteAsync(buffer2, 0, 2);

						if (isChunked) {
							// write remaining data
							if (bytesBuffered - bytesConsumed > 0) {
								responseLength += (bytesBuffered - bytesConsumed);
								await targetStream.WriteAsync(buffer, bytesConsumed, bytesBuffered - bytesConsumed);
							}

							int chunkCount = 0;
							long chunkSize = 0, chunkLength = 0;
							bool isStart = true, getMoreData = true;
							isEnd = false;
							bytesIndex = bytesConsumed;
							do {
								if (isStart) {
									getMoreData = true;
									// look for CRLF
									int linePosition;
									do {
										linePosition = Array.IndexOf(buffer, (byte)'\n', bytesIndex, bytesBuffered - bytesIndex);
										if (linePosition >= 0) {
											if (linePosition == 0 || buffer[linePosition - 1] != (byte)'\r') {
												bytesIndex = linePosition + 1;
											}
											else {
												var line = Encoding.UTF8.GetString(buffer, bytesConsumed, linePosition - bytesConsumed - 1);
												bytesConsumed = linePosition + 1;
												bytesIndex = bytesConsumed;
												isStart = false;
												if (line.Length == 0 || !long.TryParse(line, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out chunkSize) || chunkSize < 0) {
													LogWarning($"Unexpected chunk size {line}");
													ArrayPool<byte>.Shared.Return(buffer2);
													ArrayPool<byte>.Shared.Return(buffer);
													socket.Close();
													return;
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
									var bytesInBuffer = bytesBuffered - bytesConsumed;
									if (bytesInBuffer > 1) {
										if (buffer[bytesConsumed] != (byte)'\r' || buffer[bytesConsumed + 1] != (byte)'\n') {
											LogWarning($"Unexpected chunk end {buffer[bytesConsumed]:x2} {buffer[bytesConsumed + 1]:x2}");
											ArrayPool<byte>.Shared.Return(buffer2);
											ArrayPool<byte>.Shared.Return(buffer);
											socket.Close();
											return;
										}
										chunkCount++;
										if (chunkSize == 0) {
											bytesConsumed += 2;
											bytesIndex = bytesConsumed;
											getMoreData = false;
											break;
										}
										isEnd = false;
										isStart = true;
										bytesConsumed += 2;
										bytesIndex = bytesConsumed;
										responseLength += chunkSize;
										chunkLength = 0;
										chunkSize = 0;
										getMoreData = false;
									}
								}
								else {
									var remaining = chunkSize - chunkLength;
									var nextBlock = bytesBuffered - bytesConsumed;
									if (nextBlock > remaining) {
										nextBlock = (int)remaining;
									}
									bytesConsumed += nextBlock;
									bytesIndex = bytesConsumed;
									chunkLength += nextBlock;
									isEnd = chunkLength == chunkSize;
									getMoreData = !isEnd;
								}

								if (getMoreData) {
									var bytesInBuffer = bytesBuffered - bytesConsumed;
									if (bytesInBuffer > (buffer.Length / 2)) {
										// expand buffer
										var newBuffer = ArrayPool<byte>.Shared.Rent((buffer.Length < (int.MaxValue / 2)) ? buffer.Length * 2 : int.MaxValue);
										// copy the unprocessed data
										Buffer.BlockCopy(buffer, bytesConsumed, newBuffer, 0, bytesInBuffer);
										ArrayPool<byte>.Shared.Return(buffer);
										buffer = newBuffer;
									}
									else if (bytesInBuffer > 0) {
										Buffer.BlockCopy(buffer, bytesConsumed, buffer, 0, bytesInBuffer);
									}
									bytesIndex -= bytesConsumed;
									bytesConsumed = 0;

									var bytesRead = await sourceStream.ReadAsync(buffer, bytesInBuffer, buffer.Length - bytesInBuffer);
									if (bytesRead == 0) {
										LogWarning("Client closed the connection");
										unexpectedClose = true;
										break;
									}
									bytesBuffered = bytesInBuffer + bytesRead;
									await targetStream.WriteAsync(buffer, bytesInBuffer, bytesRead);
								}
							}
							while (true);

							if (unexpectedClose) {
								ArrayPool<byte>.Shared.Return(buffer2);
								ArrayPool<byte>.Shared.Return(buffer);
								socket.Close();
								return;
							}

							if (!isEnd || getMoreData) {
								ArrayPool<byte>.Shared.Return(buffer2);
								ArrayPool<byte>.Shared.Return(buffer);
								LogWarning("Unexpected request from client");
								socket.Close();
								return;
							}

							if (bytesBuffered - bytesConsumed > 0) {
								ArrayPool<byte>.Shared.Return(buffer2);
								ArrayPool<byte>.Shared.Return(buffer);
								LogWarning("Unexpected request from client");
								socket.Close();
								return;
							}
						}
						else {
							// write remaining data
							if (bytesBuffered - bytesConsumed > 0) {
								requestLength += (bytesBuffered - bytesConsumed);
								await targetStream.WriteAsync(buffer, bytesConsumed, bytesBuffered - bytesConsumed);
							}

							// read remaining data
							while (requestLength < contentLength) {
								var bytesRead = await sourceStream.ReadAsync(buffer);
								if (bytesRead == 0) {
									break;
								}

								requestLength += bytesRead;
								await targetStream.WriteAsync(buffer, 0, bytesRead);
							}

							if (requestLength != contentLength) {
								LogWarning($"Unexpected request length '{requestLength}' expected '{contentLength}'");
								ArrayPool<byte>.Shared.Return(buffer2);
								ArrayPool<byte>.Shared.Return(buffer);
								socket.Close();
								return;
							}
						}

						if (isContinue) {
							if (requestLength != 0) {
								LogWarning($"Unexpected request length '{requestLength}' for request with 'Expect: 100-continue'");
								ArrayPool<byte>.Shared.Return(buffer2);
								ArrayPool<byte>.Shared.Return(buffer);
								socket.Close();
								return;
							}
						}

						// read response
						bytesBuffered = bytesConsumed = bytesIndex = 0;
						unexpectedClose = isEnd = false;
						while (!isEnd /*&& remoteStream.DataAvailable*/) {
							var bytesInBuffer = bytesBuffered - bytesConsumed;
							if (bytesInBuffer > (buffer.Length / 2)) {
								// expand buffer
								var newBuffer = ArrayPool<byte>.Shared.Rent((buffer.Length < (int.MaxValue / 2)) ? buffer.Length * 2 : int.MaxValue);
								// copy the unprocessed data
								Buffer.BlockCopy(buffer, bytesConsumed, newBuffer, 0, bytesInBuffer);
								ArrayPool<byte>.Shared.Return(buffer);
								buffer = newBuffer;
							}
							else if (bytesInBuffer > 0) {
								Buffer.BlockCopy(buffer, bytesConsumed, buffer, 0, bytesInBuffer);
							}
							bytesIndex -= bytesConsumed;
							bytesConsumed = 0;

							var bytesRead = await targetStream.ReadAsync(buffer, bytesInBuffer, buffer.Length - bytesInBuffer);
							if (bytesRead == 0) {
								LogWarning("Server closed the connection");
								unexpectedClose = true;
								break;
							}

							bytesBuffered = bytesInBuffer + bytesRead;

							// look for CRLF | RFC 2616
							int linePosition;
							do {
								linePosition = Array.IndexOf(buffer, (byte)'\n', bytesIndex, bytesBuffered - bytesIndex);
								if (linePosition >= 0) {
									if (linePosition == 0 || buffer[linePosition - 1] != (byte)'\r') {
										bytesIndex = linePosition + 1;
									}
									else {
										var count = linePosition - bytesConsumed - 1;
										if (count > 0) {
											var line = Encoding.UTF8.GetString(buffer, bytesConsumed, count);
											responseHeaders.Add(line);
											bytesConsumed = linePosition + 1;
										}
										else {
											bytesConsumed = linePosition + 1;
											bytesIndex = bytesConsumed;
											isEnd = true;
											break;
										}
										bytesIndex = linePosition + 1;
									}
								}
							}
							while (linePosition >= 0);
						}

						if (unexpectedClose) {
							ArrayPool<byte>.Shared.Return(buffer2);
							ArrayPool<byte>.Shared.Return(buffer);
							socket.Close();
							return;
						}

						if (responseHeaders.Count == 0 || !isEnd) {
							ArrayPool<byte>.Shared.Return(buffer2);
							ArrayPool<byte>.Shared.Return(buffer);
							LogWarning("Unexpected response from server");
							socket.Close();
							return;
						}

						for (i = 0; i < responseHeaders.Count; i++) {
							var line = responseHeaders[i];
							if (line.StartsWith("Content-Length: ", StringComparison.Ordinal)) {
								if (!long.TryParse(line.Substring("Content-Length: ".Length), NumberStyles.None, CultureInfo.InvariantCulture, out contentLength)) {
									ArrayPool<byte>.Shared.Return(buffer);
									LogWarning($"Failed to parse content length '{line}'");
									socket.Close();
									return;
								}
							}
							else if (string.Equals("Transfer-Encoding: chunked", line, StringComparison.OrdinalIgnoreCase)) {
								isChunked = true;
							}
							// rewrite redirects
							//else if (line.StartsWith("Location: ", StringComparison.Ordinal)) {
							//	var target = line.Substring(10).TrimEnd('/');
							//	IProxyConfiguration proxy2 = null;
							//	foreach (var s in _settings.Proxy) {
							//		if (target.StartsWith(s.Target, StringComparison.OrdinalIgnoreCase) && (s.Target.Length == target.Length || target[s.Target.Length] == '/')) {
							//			proxy2 = s;
							//			break;
							//		}
							//	}
							//	if (proxy2 != null) {
							//		responseHeaders[i] = "Location: " + CommonUtility.CombineWithSlash((certificate != null ? Uri.UriSchemeHttps : Uri.UriSchemeHttp) + "://" + originalHost, proxy2.Path, target.Substring(proxy2.Target.Length));
							//	}
							//}
						}

						// write headers
						foreach (var header in responseHeaders) {
							var b = Encoding.UTF8.GetByteCount(header) + 2;
							if (b > buffer2.Length) {
								ArrayPool<byte>.Shared.Return(buffer2);
								buffer2 = ArrayPool<byte>.Shared.Rent(b);
							}
							int l = Encoding.UTF8.GetBytes(header, buffer2);
							buffer2[l] = (byte)'\r';
							buffer2[l + 1] = (byte)'\n';
							await sourceStream.WriteAsync(buffer2, 0, l + 2);
						}
						buffer2[0] = (byte)'\r';
						buffer2[1] = (byte)'\n';
						await sourceStream.WriteAsync(buffer2, 0, 2);

						ArrayPool<byte>.Shared.Return(buffer2);

						if (isChunked) {
							// write remaining data
							if (bytesBuffered - bytesConsumed > 0) {
								responseLength += (bytesBuffered - bytesConsumed);
								await sourceStream.WriteAsync(buffer, bytesConsumed, bytesBuffered - bytesConsumed);
							}

							int chunkCount = 0;
							long chunkSize = 0, chunkLength = 0;
							bool isStart = true, getMoreData = true;
							isEnd = false;
							bytesIndex = bytesConsumed;
							do {
								if (isStart) {
									getMoreData = true;
									// look for CRLF
									int linePosition;
									do {
										linePosition = Array.IndexOf(buffer, (byte)'\n', bytesIndex, bytesBuffered - bytesIndex);
										if (linePosition >= 0) {
											if (linePosition == 0 || buffer[linePosition - 1] != (byte)'\r') {
												bytesIndex = linePosition + 1;
											}
											else {
												var line = Encoding.UTF8.GetString(buffer, bytesConsumed, linePosition - bytesConsumed - 1);
												bytesConsumed = linePosition + 1;
												bytesIndex = bytesConsumed;
												isStart = false;
												if (line.Length == 0 || !long.TryParse(line, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out chunkSize) || chunkSize < 0) {
													LogWarning($"Unexpected chunk size {line}");
													ArrayPool<byte>.Shared.Return(buffer);
													socket.Close();
													return;
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
									var bytesInBuffer = bytesBuffered - bytesConsumed;
									if (bytesInBuffer > 1) {
										if (buffer[bytesConsumed] != (byte)'\r' || buffer[bytesConsumed + 1] != (byte)'\n') {
											LogWarning($"Unexpected chunk end {buffer[bytesConsumed]:x2} {buffer[bytesConsumed + 1]:x2}");
											ArrayPool<byte>.Shared.Return(buffer);
											socket.Close();
											return;
										}
										chunkCount++;
										if (chunkSize == 0) {
											bytesConsumed += 2;
											bytesIndex = bytesConsumed;
											getMoreData = false;
											break;
										}
										isEnd = false;
										isStart = true;
										bytesConsumed += 2;
										bytesIndex = bytesConsumed;
										responseLength += chunkSize;
										chunkLength = 0;
										chunkSize = 0;
										getMoreData = false;
									}
								}
								else {
									var remaining = chunkSize - chunkLength;
									var nextBlock = bytesBuffered - bytesConsumed;
									if (nextBlock > remaining) {
										nextBlock = (int)remaining;
									}
									bytesConsumed += nextBlock;
									bytesIndex = bytesConsumed;
									chunkLength += nextBlock;
									isEnd = chunkLength == chunkSize;
									getMoreData = !isEnd;
								}

								if (getMoreData) {
									var bytesInBuffer = bytesBuffered - bytesConsumed;
									if (bytesInBuffer > (buffer.Length / 2)) {
										// expand buffer
										var newBuffer = ArrayPool<byte>.Shared.Rent((buffer.Length < (int.MaxValue / 2)) ? buffer.Length * 2 : int.MaxValue);
										// copy the unprocessed data
										Buffer.BlockCopy(buffer, bytesConsumed, newBuffer, 0, bytesInBuffer);
										ArrayPool<byte>.Shared.Return(buffer);
										buffer = newBuffer;
									}
									else if (bytesInBuffer > 0) {
										Buffer.BlockCopy(buffer, bytesConsumed, buffer, 0, bytesInBuffer);
									}
									bytesIndex -= bytesConsumed;
									bytesConsumed = 0;

									var bytesRead = await targetStream.ReadAsync(buffer, bytesInBuffer, buffer.Length - bytesInBuffer);
									if (bytesRead == 0) {
										LogWarning("Server closed the connection");
										unexpectedClose = true;
										break;
									}
									bytesBuffered = bytesInBuffer + bytesRead;
									await sourceStream.WriteAsync(buffer, bytesInBuffer, bytesRead);
								}
							}
							while (true);

							if (unexpectedClose) {
								ArrayPool<byte>.Shared.Return(buffer);
								socket.Close();
								return;
							}

							if (!isEnd || getMoreData) {
								ArrayPool<byte>.Shared.Return(buffer);
								LogWarning("Unexpected response from server");
								socket.Close();
								return;
							}

							if (bytesBuffered - bytesConsumed > 0) {
								ArrayPool<byte>.Shared.Return(buffer);
								LogWarning("Unexpected response from server");
								socket.Close();
								return;
							}
						}
						else {
							// write remaining data
							if (bytesBuffered - bytesConsumed > 0) {
								responseLength += (bytesBuffered - bytesConsumed);
								await sourceStream.WriteAsync(buffer, bytesConsumed, bytesBuffered - bytesConsumed);
							}

							// read remaining data
							while (responseLength < contentLength) {
								var bytesRead = await targetStream.ReadAsync(buffer);
								if (bytesRead == 0) {
									break;
								}

								responseLength += bytesRead;
								await sourceStream.WriteAsync(buffer, 0, bytesRead);
							}

							if (contentLength != responseLength) {
								LogWarning($"Unexpected response length {responseLength} expected {contentLength}");
							}
						}

						if (targetSslStream != null) {
							await targetSslStream.DisposeAsync();
						}
					}
				}

				ArrayPool<byte>.Shared.Return(buffer);

				if (sourceSslStream != null) {
					await sourceSslStream.DisposeAsync();
				}

				socket.Close();
			}
			LogInformation("Request completed");
		}

		private static IFarmSettings GetFarSettings(IConfiguration config) {
			var appSettings = new FarmSettingsValues();
			config.GetSection("FarmSettings").Bind(appSettings);

			string json;
			using (var file = File.Open(appSettings.ConfigPath + "\\HttpProxy.global.js", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
				using (var sr = new StreamReader(file, Encoding.UTF8, false)) {
					json = sr.ReadToEnd();
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
