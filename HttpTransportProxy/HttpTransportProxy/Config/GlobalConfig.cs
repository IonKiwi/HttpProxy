using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace HttpTransportProxy.Config {
	public class GlobalConfig : IFarmSettings {
		public List<ServerBinding> ServerBindings {
			get;
			set;
		}

		public List<ProxyConfiguration> Proxy {
			get;
			set;
		}

		public void Init() {
			if (ServerBindings != null) {
				foreach (var sb in ServerBindings) {
					sb.Init();
				}
			}
			if (Proxy != null) {
				foreach (var p in Proxy) {
					p.Init();
				}
			}
		}

		IReadOnlyList<IServerBinding> IFarmSettings.ServerBindings => ServerBindings;

		IReadOnlyList<IProxyConfiguration> IFarmSettings.Proxy => Proxy;
	}
}
