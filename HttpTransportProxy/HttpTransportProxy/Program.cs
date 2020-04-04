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
using System.Net.Sockets;
using System.Runtime.InteropServices;
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
			await Task.Run(acceptAction);

			Console.WriteLine("Completed");
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
						Console.WriteLine($"Listening on port {kv.Port}");
						listenSocket.Listen(120);
						sockets.Add((listenSocket, null));
						tasks.Add(listenSocket.AcceptAsync());
					}
					else {
						// secure binding
						var listenSocket = new Socket(SocketType.Stream, ProtocolType.Tcp);
						listenSocket.Bind(new IPEndPoint(ipAddress, kv.Port));
						Console.WriteLine($"Listening on port {kv.Port}");
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
			Console.WriteLine($"Accepted connection from {socket.RemoteEndPoint}");

			byte[] buffer = ArrayPool<byte>.Shared.Rent(1024);
			int bytesBuffered = 0, bytesConsumed = 0, bytesIndex = 0;
			bool unexpectedClose = false, isEnd = false;
			List<string> headers = new List<string>(10);
			long requestLength = 0;
			using (var stream = new NetworkStream(socket, FileAccess.ReadWrite, false)) {

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

					var bytesRead = await stream.ReadAsync(buffer, bytesInBuffer, buffer.Length - bytesInBuffer);
					if (bytesRead == 0) {
						Console.WriteLine("Client closed the connection");
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
					Console.WriteLine("Unexpected request from client");
					socket.Close();
					return;
				}

				int i = headers[0].IndexOf(' ');
				if (i < 0) {
					ArrayPool<byte>.Shared.Return(buffer);
					Console.WriteLine("Unexpected request from client");
					socket.Close();
					return;
				}

				string verb = headers[0].Substring(0, i);
				int i2 = headers[0].IndexOf(' ', i + 1);
				if (i2 < 0) {
					ArrayPool<byte>.Shared.Return(buffer);
					Console.WriteLine("Unexpected request from client");
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
					Console.WriteLine($"No proxy configuration for request to {destination}");
					socket.Close();
					return;
				}

				var targetUri = new Uri(proxy.Target, UriKind.Absolute);
				bool isContinue = false, isChunked = false;
				long contentLength = 0;
				for (i = 0; i < headers.Count; i++) {
					var line = headers[i];
					if (string.Equals("Expect: 100-continue", line, StringComparison.Ordinal)) {
						isContinue = true;
					}
					else if (line.StartsWith("Content-Length: ", StringComparison.Ordinal)) {
						if (!long.TryParse(line.Substring("Content-Length: ".Length), NumberStyles.None, CultureInfo.InvariantCulture, out contentLength)) {
							ArrayPool<byte>.Shared.Return(buffer);
							Console.WriteLine($"Failed to parse content length '{line}'");
							socket.Close();
							return;
						}
					}
					else if (string.Equals("Transfer-Encoding: chunked", line, StringComparison.OrdinalIgnoreCase)) {
						isChunked = true;
					}
					else if (line.StartsWith("Host: ", StringComparison.Ordinal)) {
						headers[i] = "Host: " + targetUri.Host;
					}
				}

				IPAddress[] serverIps = Dns.GetHostAddresses(targetUri.DnsSafeHost);
				if (serverIps == null || serverIps.Length == 0) {
					Console.WriteLine($"Failed to resolve addresses of {proxy.Target}");
					socket.Close();
					return;
				}
				int connectPort = targetUri.Port;
				using (var remoteSocket = new Socket(SocketType.Stream, ProtocolType.Tcp)) {
					await remoteSocket.ConnectAsync(serverIps, connectPort);

					using (var remoteStream = new NetworkStream(remoteSocket, FileAccess.ReadWrite, false)) {

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
							await remoteStream.WriteAsync(buffer2, 0, l + 2);
						}
						buffer2[0] = (byte)'\r';
						buffer2[1] = (byte)'\n';
						await remoteStream.WriteAsync(buffer2, 0, 2);

						// write remaining data
						if (bytesBuffered - bytesConsumed > 0) {
							requestLength += (bytesBuffered - bytesConsumed);
							await remoteStream.WriteAsync(buffer, bytesConsumed, bytesBuffered - bytesConsumed);
						}

						// read remaining data
						while (stream.DataAvailable) {
							var bytesRead = await stream.ReadAsync(buffer);
							if (bytesRead == 0) {
								break;
							}

							requestLength += bytesRead;
							await remoteStream.WriteAsync(buffer, 0, bytesRead);
						}

						if (isContinue) {
							if (requestLength != 0) {
								Console.WriteLine($"Unexpected request length '{requestLength}' for request with 'Expect: 100-continue'");
								ArrayPool<byte>.Shared.Return(buffer2);
								ArrayPool<byte>.Shared.Return(buffer);
								socket.Close();
								return;
							}
						}
						else if (requestLength != contentLength) {
							Console.WriteLine($"Unexpected request length '{requestLength}' expected '{contentLength}'");
							ArrayPool<byte>.Shared.Return(buffer2);
							ArrayPool<byte>.Shared.Return(buffer);
							socket.Close();
							return;
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

							var bytesRead = await remoteStream.ReadAsync(buffer, bytesInBuffer, buffer.Length - bytesInBuffer);
							if (bytesRead == 0) {
								Console.WriteLine("Server closed the connection");
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
							Console.WriteLine("Unexpected response from server");
							socket.Close();
							return;
						}

						for (i = 0; i < responseHeaders.Count; i++) {
							var line = responseHeaders[i];
							if (line.StartsWith("Content-Length: ", StringComparison.Ordinal)) {
								if (!long.TryParse(line.Substring("Content-Length: ".Length), NumberStyles.None, CultureInfo.InvariantCulture, out contentLength)) {
									ArrayPool<byte>.Shared.Return(buffer);
									Console.WriteLine($"Failed to parse content length '{line}'");
									socket.Close();
									return;
								}
							}
							else if (string.Equals("Transfer-Encoding: chunked", line, StringComparison.OrdinalIgnoreCase)) {
								isChunked = true;
							}
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
							await stream.WriteAsync(buffer2, 0, l + 2);
						}
						buffer2[0] = (byte)'\r';
						buffer2[1] = (byte)'\n';
						await stream.WriteAsync(buffer2, 0, 2);

						// write remaining data
						if (bytesBuffered - bytesConsumed > 0) {
							responseLength += (bytesBuffered - bytesConsumed);
							await stream.WriteAsync(buffer, bytesConsumed, bytesBuffered - bytesConsumed);
						}

						// read remaining data
						while (remoteStream.DataAvailable) {
							var bytesRead = await remoteStream.ReadAsync(buffer);
							if (bytesRead == 0) {
								break;
							}

							responseLength += bytesRead;
							await stream.WriteAsync(buffer, 0, bytesRead);
						}

						ArrayPool<byte>.Shared.Return(buffer2);

						if (contentLength != responseLength) {
							Console.WriteLine($"Unexpected response length {responseLength} expected {contentLength}");
						}
					}
				}

				ArrayPool<byte>.Shared.Return(buffer);
				socket.Close();
			}
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
	}
}
