using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HttpProxy.Config {
	public interface IFarmSettings {
		public IReadOnlyList<IServerBinding> ServerBindings {
			get;
		}

		public IReadOnlyList<IProxyConfiguration> Proxy {
			get;
		}
	}
}
