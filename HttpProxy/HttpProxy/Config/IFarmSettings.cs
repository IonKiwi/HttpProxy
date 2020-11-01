using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HttpProxy.Config {
	public interface IFarmSettings {
		IReadOnlyList<IServerBinding> ServerBindings { get; }

		IReadOnlyList<IProxyConfiguration> Proxy { get; }
	}
}
