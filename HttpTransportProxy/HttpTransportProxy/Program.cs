using HttpTransportProxy.Config;
using HttpTransportProxy.PlatformSpecific;
using HttpTransportProxy.Utilities;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace HttpTransportProxy {
	class Program {

		private static bool _isWindows;

		static async Task Main(string[] args) {
			_isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
			IConfiguration config = GetConfiguration();
			var farmSettings = GetFarSettings(config);

			Func<Task> acceptAction = () => Accept(farmSettings);
			await Task.Run(acceptAction);

			Console.WriteLine("Completed");
		}

		private static async Task Accept(IFarmSettings farmSettings) {
			var ipAddress = IPAddress.Any;
			var sockets = new List<(Socket socket, X509Certificate2 certificate)>();
			var tasks = new List<Task<Socket>>();

			var serverBindings = farmSettings.ServerBindings;
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
						tasks[i] = sockets[i].socket.AcceptAsync();
						Func<Task> acceptAction = () => HandleConnection(t.Result, sockets[i].certificate);
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
