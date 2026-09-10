package appconfig

// Clone isolates mutable maps and slices before validation or live publication.
func (c Config) Clone() Config {
	c.GatewayAllowIPs = append([]string(nil), c.GatewayAllowIPs...)
	if c.Gateways != nil {
		instances := make(map[string]GatewayInstance, len(c.Gateways))
		for id, instance := range c.Gateways {
			instance.GatewayAllowIPs = append([]string(nil), instance.GatewayAllowIPs...)
			instances[id] = instance
		}
		c.Gateways = instances
	}
	if c.Gateway != nil {
		legacy := *c.Gateway
		legacy.GatewayAllowIPs = append([]string(nil), legacy.GatewayAllowIPs...)
		c.Gateway = &legacy
	}
	if c.AutoStart != nil {
		value := *c.AutoStart
		c.AutoStart = &value
	}
	return c
}
