package config

import "errors"

var (
	ErrFeishuTenantRequired      = errors.New("feishu: at least one tenant option is required")
	ErrFeishuTenantKeyRequired   = errors.New("feishu: tenant option requires tenant_key")
	ErrFeishuTenantAppIDMissing  = errors.New("feishu: tenant option requires client_id")
	ErrFeishuTenantSecretMissing = errors.New("feishu: tenant option requires client_secret")
)

func ValidateFeishuConfig(cfg FeishuConnectConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.TenantOptions) == 0 {
		return ErrFeishuTenantRequired
	}
	for _, option := range cfg.TenantOptions {
		if option.TenantKey == "" {
			return ErrFeishuTenantKeyRequired
		}
		if option.ClientID == "" {
			return ErrFeishuTenantAppIDMissing
		}
		if option.ClientSecret == "" {
			return ErrFeishuTenantSecretMissing
		}
	}
	return nil
}
