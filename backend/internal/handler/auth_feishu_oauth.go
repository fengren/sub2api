package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	//nolint:depguard // FeishuQRStore is initialized from routes with the shared Redis client; keep this narrow until the store moves out of handler.
	"github.com/redis/go-redis/v9"
)

const (
	feishuOAuthCookiePath         = "/api/v1/auth/oauth/feishu"
	feishuOAuthStateCookieName    = "feishu_oauth_state"
	feishuOAuthRedirectCookie     = "feishu_oauth_redirect"
	feishuOAuthIntentCookieName   = "feishu_oauth_intent"
	feishuOAuthBindUserCookieName = "feishu_oauth_bind_user"
	feishuOAuthCookieMaxAgeSec    = 600
	feishuOAuthDefaultRedirectTo  = "/dashboard"
	feishuOAuthDefaultFrontendCB  = "/auth/feishu/callback"
	feishuQRRedisKeyPrefix        = "feishu:qr:"
	feishuQRTTL                   = 5 * time.Minute
)

// feishuQRStore 扫码状态存储（Redis）
var (
	feishuQRStore     *FeishuQRStore
	feishuQRStoreOnce sync.Once
)

// FeishuQRStore 包装 Redis 操作，提供扫码状态存取
type FeishuQRStore struct {
	client *redis.Client
}

func (s *FeishuQRStore) isReady() bool { return s != nil && s.client != nil }

// FeishuQRState 存储在 Redis 中的扫码状态
type FeishuQRState struct {
	TicketID            string    `json:"ticket_id"`
	State               string    `json:"state"`
	Status              string    `json:"status"` // pending, scanned, confirmed, expired, cancelled
	Code                string    `json:"code,omitempty"`
	RedirectTo          string    `json:"redirect_to,omitempty"`
	Intent              string    `json:"intent,omitempty"`
	BrowserSessionKey   string    `json:"browser_session_key,omitempty"`
	FeishuToken         string    `json:"feishu_token,omitempty"`
	SelectedTenantKey   string    `json:"selected_tenant_key,omitempty"`
	FlowKey             string    `json:"flow_key,omitempty"`
	PendingSessionToken string    `json:"pending_session_token,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

const (
	feishuQRStatusPending   = "pending"
	feishuQRStatusScanned   = "scanned"
	feishuQRStatusConfirmed = "confirmed"
	feishuQRStatusExpired   = "expired"
	feishuQRStatusCancelled = "cancelled"
)

var errFeishuQRStoreUnavailable = infraerrors.ServiceUnavailable("QR_STORE_UNAVAILABLE", "feishu qr session store is not available")

type feishuOAuthClient struct {
	cfg        config.FeishuConnectConfig
	httpClient *http.Client
}

type feishuOAuthProfile struct {
	OpenID    string
	UnionID   string
	TenantKey string
	Email     string
	Name      string
	AvatarURL string
	Raw       map[string]any
}

type feishuOAuthPreparedSession struct {
	cfg               config.FeishuConnectConfig
	state             string
	redirectTo        string
	intent            string
	browserSessionKey string
	selectedTenantKey string
}

type feishuOAuthQRInitResponse struct {
	TicketID  string `json:"ticket_id"`
	QRURL     string `json:"qr_url"`
	GotoURL   string `json:"goto_url"`
	SDKURL    string `json:"sdk_url"`
	ExpiresIn int    `json:"expires_in"`
}

// InitFeishuQRStore 初始化扫码状态存储，应在路由注册时调用一次
func InitFeishuQRStore(client *redis.Client) {
	feishuQRStoreOnce.Do(func() {
		feishuQRStore = &FeishuQRStore{client: client}
	})
}

func (s *FeishuQRStore) redisKey(ticketID string) string {
	return feishuQRRedisKeyPrefix + ticketID
}

func (s *FeishuQRStore) CreateTicket(ctx context.Context, ticketID, state string) error {
	return s.CreateTicketFull(ctx, ticketID, state, "", "", "", "", "", "")
}

func (s *FeishuQRStore) CreateTicketWithSession(ctx context.Context, ticketID, state, redirectTo, intent, browserSessionKey string) error {
	return s.CreateTicketFull(ctx, ticketID, state, redirectTo, intent, browserSessionKey, "", "", "")
}

func (s *FeishuQRStore) CreateTicketFull(ctx context.Context, ticketID, state, redirectTo, intent, browserSessionKey, feishuToken, selectedTenantKey, flowKey string) error {
	if !s.isReady() {
		return errFeishuQRStoreUnavailable
	}
	st := FeishuQRState{
		TicketID:          ticketID,
		State:             state,
		Status:            feishuQRStatusPending,
		RedirectTo:        redirectTo,
		Intent:            intent,
		BrowserSessionKey: browserSessionKey,
		FeishuToken:       feishuToken,
		SelectedTenantKey: strings.TrimSpace(selectedTenantKey),
		FlowKey:           flowKey,
		CreatedAt:         time.Now(),
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	pipe := s.client.Pipeline()
	pipe.Set(ctx, s.redisKey(ticketID), data, feishuQRTTL)
	// 二级索引：feishu_token → ticket_id，用于 verify 回调查找
	if feishuToken != "" {
		pipe.Set(ctx, feishuQRRedisKeyPrefix+"token:"+feishuToken, ticketID, feishuQRTTL)
	}
	_, err = pipe.Exec(ctx)
	return err
}

// GetByFeishuToken 通过飞书 token 查找 QR 状态
func (s *FeishuQRStore) GetByFeishuToken(ctx context.Context, feishuToken string) (*FeishuQRState, error) {
	if !s.isReady() {
		return nil, errFeishuQRStoreUnavailable
	}
	ticketID, err := s.client.Get(ctx, feishuQRRedisKeyPrefix+"token:"+feishuToken).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetStatus(ctx, ticketID)
}

func (s *FeishuQRStore) GetStatus(ctx context.Context, ticketID string) (*FeishuQRState, error) {
	if !s.isReady() {
		return nil, errFeishuQRStoreUnavailable
	}
	data, err := s.client.Get(ctx, s.redisKey(ticketID)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st FeishuQRState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *FeishuQRStore) MarkConfirmedWithSession(ctx context.Context, ticketID, code, redirectTo, pendingSessionToken string) error {
	if !s.isReady() {
		return errFeishuQRStoreUnavailable
	}
	st, err := s.GetStatus(ctx, ticketID)
	if err != nil || st == nil {
		return err
	}
	st.Status = feishuQRStatusConfirmed
	if code != "" {
		st.Code = code
	}
	if redirectTo != "" {
		st.RedirectTo = redirectTo
	}
	if pendingSessionToken != "" {
		st.PendingSessionToken = pendingSessionToken
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	// 确认后短暂保留状态，便于 OAuth callback 和前端完成跳转。
	return s.client.Set(ctx, s.redisKey(ticketID), data, 30*time.Second).Err()
}

func (s *FeishuQRStore) MarkScanned(ctx context.Context, ticketID string) error {
	if !s.isReady() {
		return errFeishuQRStoreUnavailable
	}
	st, err := s.GetStatus(ctx, ticketID)
	if err != nil || st == nil {
		return err
	}
	st.Status = feishuQRStatusScanned
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.redisKey(ticketID), data, feishuQRTTL).Err()
}

func (h *AuthHandler) getFeishuOAuthConfig(ctx context.Context) (config.FeishuConnectConfig, error) {
	if h != nil && h.settingSvc != nil {
		return h.settingSvc.GetFeishuConnectOAuthConfig(ctx)
	}
	if h == nil || h.cfg == nil {
		return config.FeishuConnectConfig{}, infraerrors.ServiceUnavailable("CONFIG_NOT_READY", "config not loaded")
	}
	if !h.cfg.Feishu.Enabled {
		return config.FeishuConnectConfig{}, infraerrors.NotFound("OAUTH_DISABLED", "feishu oauth login is disabled")
	}
	return h.cfg.Feishu, nil
}

func setFeishuCookie(c *gin.Context, name string, value string, maxAgeSec int, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: value, Path: feishuOAuthCookiePath, MaxAge: maxAgeSec,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func clearFeishuCookie(c *gin.Context, name string, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: "", Path: feishuOAuthCookiePath, MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func generateCSPNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fallback: 不会真正发生，但避免 panic
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (h *AuthHandler) FeishuOAuthStart(c *gin.Context) {
	prepared, err := h.prepareFeishuOAuthSession(c)
	if err != nil {
		redirectOAuthError(c, feishuOAuthDefaultFrontendCB, "feishu_not_enabled", "", "")
		return
	}
	authURL, err := buildFeishuAuthorizeURL(prepared.cfg, prepared.state)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

func (h *AuthHandler) FeishuOAuthQRInit(c *gin.Context) {
	if feishuQRStore == nil || !feishuQRStore.isReady() {
		response.Error(c, http.StatusServiceUnavailable, "QR_STORE_UNAVAILABLE")
		return
	}

	prepared, err := h.prepareFeishuOAuthSession(c)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	ticketID := uuid.New().String()
	if err := feishuQRStore.CreateTicketFull(c.Request.Context(), ticketID, ticketID,
		prepared.redirectTo, prepared.intent, prepared.browserSessionKey,
		ticketID, prepared.selectedTenantKey, ""); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	// 飞书 OAuth 授权 URL（passport.feishu.cn 页面自带扫码界面）
	authURL, err := buildFeishuAuthorizeURL(prepared.cfg, ticketID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	qrPageURL := buildFeishuQRPageURL(prepared.cfg.Region, authURL)

	response.Success(c, feishuOAuthQRInitResponse{
		TicketID:  ticketID,
		QRURL:     qrPageURL,
		GotoURL:   authURL,
		SDKURL:    feishuQRSDKURL(prepared.cfg.Region),
		ExpiresIn: int(feishuQRTTL.Seconds()),
	})
}

func (h *AuthHandler) FeishuOAuthQRPage(c *gin.Context) {
	gotoURL := strings.TrimSpace(c.Query("goto"))
	region := strings.ToLower(strings.TrimSpace(c.Query("region")))
	if gotoURL == "" {
		response.Error(c, http.StatusBadRequest, "MISSING_GOTO")
		return
	}
	if !isAllowedFeishuAuthorizeURL(gotoURL) {
		response.Error(c, http.StatusBadRequest, "INVALID_GOTO")
		return
	}

	sdkURL := feishuQRSDKURL(region)
	gotoJSON, _ := json.Marshal(gotoURL)
	nonce := generateCSPNonce()

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("X-Frame-Options", "SAMEORIGIN")
	c.Header("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"script-src 'nonce-" + nonce + "' " + sdkURL,
		"style-src 'nonce-" + nonce + "'",
		"img-src data: https:",
		"frame-src https://passport.feishu.cn https://accounts.feishu.cn https://passport.larksuite.com https://accounts.larksuite.com",
		"connect-src https:",
		"base-uri 'none'",
		"frame-ancestors 'self'",
	}, "; "))

	nonceAttr := ` nonce="` + nonce + `"`
	page := fmt.Sprintf(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Feishu QR Login</title>
  <style%s>
    html, body { margin: 0; width: 100%%; height: 100%%; background: #fff; overflow: hidden; }
    body { display: flex; align-items: center; justify-content: center; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    #login_container { width: 300px; height: 360px; display: flex; align-items: center; justify-content: center; }
    .error { padding: 16px; color: #6b7280; font-size: 14px; text-align: center; }
  </style>
</head>
<body>
  <div id="login_container"></div>
  <script%s src="%s"></script>
  <script%s>
    (function () {
      var gotoURL = %s;
      var container = document.getElementById('login_container');
      function debug(step, detail) {
        try {
          window.parent.postMessage({
            type: 'feishu_qr_debug',
            step: step,
            detail: detail || ''
          }, window.location.origin);
        } catch (_) {}
      }
      function showError(message) {
        container.innerHTML = '<div class="error">' + message + '</div>';
        debug('error', message);
      }
      function extractTmpCode(data) {
        if (!data) return '';
        if (typeof data === 'string') {
          try {
            var parsed = JSON.parse(data);
            return extractTmpCode(parsed);
          } catch (_) {
            return data;
          }
        }
        if (typeof data.tmp_code === 'string') return data.tmp_code;
        if (data.step_info && typeof data.step_info.tmp_code === 'string') return data.step_info.tmp_code;
        if (data.data) return extractTmpCode(data.data);
        return '';
      }
      function isTrustedFeishuOrigin(origin) {
        try {
          var host = new URL(origin).hostname;
          return host === 'passport.feishu.cn' ||
            host === 'accounts.feishu.cn' ||
            host === 'login.feishu.cn' ||
            host === 'www.feishu.cn' ||
            host === 'passport.larksuite.com' ||
            host === 'accounts.larksuite.com' ||
            host === 'login.larksuite.com' ||
            host === 'www.larksuite.com';
        } catch (_) {
          return false;
        }
      }
      debug('wrapper_loaded');
      if (typeof QRLogin !== 'function') {
        showError('Feishu QR SDK failed to load');
        return;
      }
      var qrLogin = QRLogin({
        id: 'login_container',
        goto: gotoURL,
        width: '300',
        height: '360',
        style: 'width:300px;height:360px;border:0;'
      });
      debug('sdk_initialized');
      function handleMessage(event) {
        var matchesSDKOrigin = qrLogin && typeof qrLogin.matchOrigin === 'function' && qrLogin.matchOrigin(event.origin);
        debug('message_received', event.origin);
        if (!matchesSDKOrigin && !isTrustedFeishuOrigin(event.origin)) {
          debug('message_rejected', event.origin);
          return;
        }
        var tmpCode = extractTmpCode(event.data);
        if (!tmpCode) {
          debug('tmp_code_missing');
          return;
        }
        var separator = gotoURL.indexOf('?') === -1 ? '?' : '&';
        var nextURL = gotoURL + separator + 'tmp_code=' + encodeURIComponent(tmpCode);
        debug('tmp_code_received');
        try {
          window.top.location.href = nextURL;
        } catch (_) {
          window.parent.location.href = nextURL;
        }
      }
      if (window.addEventListener) {
        window.addEventListener('message', handleMessage, false);
      } else if (window.attachEvent) {
        window.attachEvent('onmessage', handleMessage);
      }
    })();
	</script>
</body>
</html>`, nonceAttr, nonceAttr, html.EscapeString(sdkURL), nonceAttr, string(gotoJSON))

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

// FeishuOAuthQRVerify 处理飞书扫码验证回调。
// 当用户扫码时，飞书会向配置的"登录验证网址"发起请求，携带 token 参数。
// 此端点验证 token 是否存在并返回飞书期望的响应格式。
func (h *AuthHandler) FeishuOAuthQRVerify(c *gin.Context) {
	if feishuQRStore == nil || !feishuQRStore.isReady() {
		c.JSON(http.StatusOK, gin.H{"err_no": 0, "data": gin.H{"is_valid": false}})
		return
	}

	token := strings.TrimSpace(c.Query("token"))
	if token == "" {
		// 也尝试从 POST body 读取
		var body struct {
			Token string `json:"token"`
		}
		if err := c.ShouldBindJSON(&body); err == nil {
			token = strings.TrimSpace(body.Token)
		}
	}
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"err_no": 400, "err_msg": "missing token"})
		return
	}

	st, err := feishuQRStore.GetByFeishuToken(c.Request.Context(), token)
	if err != nil || st == nil {
		c.JSON(http.StatusOK, gin.H{"err_no": 0, "data": gin.H{"is_valid": false}})
		return
	}

	// token 有效，标记为 scanned
	_ = feishuQRStore.MarkScanned(c.Request.Context(), st.TicketID)

	cfg, _ := h.getFeishuOAuthConfig(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{
		"err_no":  0,
		"err_msg": "",
		"data": gin.H{
			"is_valid":     true,
			"redirect_url": strings.TrimSpace(cfg.RedirectURL),
		},
	})
}

func (h *AuthHandler) FeishuOAuthCallback(c *gin.Context) {
	cfg, cfgErr := h.getFeishuOAuthConfig(c.Request.Context())
	if cfgErr != nil {
		response.ErrorFrom(c, cfgErr)
		return
	}
	frontendCallback := strings.TrimSpace(cfg.FrontendRedirectURL)
	if frontendCallback == "" {
		frontendCallback = feishuOAuthDefaultFrontendCB
	}
	if providerErr := strings.TrimSpace(c.Query("error")); providerErr != "" {
		redirectOAuthError(c, frontendCallback, "provider_error", providerErr, c.Query("error_description"))
		return
	}
	code := strings.TrimSpace(c.Query("code"))
	state := strings.TrimSpace(c.Query("state"))
	if code == "" || state == "" {
		redirectOAuthError(c, frontendCallback, "missing_params", "missing code/state", "")
		return
	}

	secureCookie := isRequestHTTPS(c)

	// 优先从 cookie 读取会话数据（标准重定向流程）；
	// 若无 cookie，则从 QR store 读取（扫码登录流程：state 即 ticket_id）。
	redirectTo := ""
	intent := ""
	browserSessionKey := ""
	selectedTenantKey := ""
	qrTicketID := ""

	expectedState, cookieErr := readCookieDecoded(c, feishuOAuthStateCookieName)
	if cookieErr == nil && state == expectedState {
		// 标准重定向流程：从 cookie 读取
		redirectTo, _ = readCookieDecoded(c, feishuOAuthRedirectCookie)
		intent, _ = readCookieDecoded(c, feishuOAuthIntentCookieName)
		browserSessionKey, _ = readOAuthPendingBrowserCookie(c)
		defer func() {
			clearFeishuCookie(c, feishuOAuthStateCookieName, secureCookie)
			clearFeishuCookie(c, feishuOAuthRedirectCookie, secureCookie)
			clearFeishuCookie(c, feishuOAuthIntentCookieName, secureCookie)
		}()
	} else {
		// 扫码登录流程：从 QR store 读取会话数据
		if feishuQRStore == nil || !feishuQRStore.isReady() {
			redirectOAuthError(c, frontendCallback, "session_error", "qr session store unavailable", "")
			return
		}
		qrState, qrErr := feishuQRStore.GetStatus(c.Request.Context(), state)
		if qrErr != nil || qrState == nil {
			redirectOAuthError(c, frontendCallback, "csrf", "state mismatch", "")
			return
		}
		redirectTo = qrState.RedirectTo
		intent = qrState.Intent
		browserSessionKey = qrState.BrowserSessionKey
		selectedTenantKey = strings.TrimSpace(qrState.SelectedTenantKey)
		qrTicketID = state
	}

	redirectTo = sanitizeFrontendRedirectPath(redirectTo)
	if redirectTo == "" {
		redirectTo = feishuOAuthDefaultRedirectTo
	}
	intent = normalizeOAuthIntent(intent)
	if strings.TrimSpace(browserSessionKey) == "" {
		redirectOAuthError(c, frontendCallback, "missing_browser_session", "missing browser session", "")
		return
	}

	cfg = applySelectedFeishuTenantConfig(cfg, selectedTenantKey)
	client := &feishuOAuthClient{cfg: cfg, httpClient: &http.Client{Timeout: 10 * time.Second}}
	profile, err := client.FetchProfile(c.Request.Context(), code)
	if err != nil {
		slog.Error("feishu oauth upstream call failed", "error", err.Error())
		redirectOAuthError(c, frontendCallback, "upstream_error", infraerrors.Message(err), "")
		return
	}
	subject := firstNonEmpty(profile.UnionID, profile.OpenID)
	if subject == "" {
		redirectOAuthError(c, frontendCallback, "userinfo_failed", "missing feishu user id", "")
		return
	}
	slog.Info("feishu oauth tenant debug",
		"oauth_client_id", strings.TrimSpace(cfg.ClientID),
		"selected_tenant_key", selectedTenantKey,
		"profile_tenant_key", strings.TrimSpace(profile.TenantKey),
		"configured_tenant_options", feishuTenantOptionLogValues(cfg),
		"open_id", strings.TrimSpace(profile.OpenID),
		"union_id", strings.TrimSpace(profile.UnionID),
		"email", strings.TrimSpace(profile.Email),
	)
	if !checkFeishuTenantAllowed(cfg, profile.TenantKey) {
		slog.Warn("feishu oauth tenant rejected",
			"reason", "not_allowed",
			"oauth_client_id", strings.TrimSpace(cfg.ClientID),
			"selected_tenant_key", selectedTenantKey,
			"profile_tenant_key", strings.TrimSpace(profile.TenantKey),
			"configured_tenant_options", feishuTenantOptionLogValues(cfg),
			"open_id", strings.TrimSpace(profile.OpenID),
			"union_id", strings.TrimSpace(profile.UnionID),
			"email", strings.TrimSpace(profile.Email),
		)
		redirectOAuthError(c, frontendCallback, "tenant_rejected", "feishu tenant not allowed", "")
		return
	}
	if selectedTenantKey != "" && selectedTenantKey != strings.TrimSpace(profile.TenantKey) {
		slog.Warn("feishu oauth tenant rejected",
			"reason", "selected_tenant_mismatch",
			"oauth_client_id", strings.TrimSpace(cfg.ClientID),
			"selected_tenant_key", selectedTenantKey,
			"profile_tenant_key", strings.TrimSpace(profile.TenantKey),
			"configured_tenant_options", feishuTenantOptionLogValues(cfg),
			"open_id", strings.TrimSpace(profile.OpenID),
			"union_id", strings.TrimSpace(profile.UnionID),
			"email", strings.TrimSpace(profile.Email),
		)
		redirectOAuthError(c, frontendCallback, "tenant_rejected", "selected feishu tenant does not match login tenant", "")
		return
	}
	identityKey := service.PendingAuthIdentityKey{ProviderType: "feishu", ProviderKey: "feishu", ProviderSubject: subject}
	upstreamClaims := buildFeishuUpstreamClaims(profile)

	if intent == oauthIntentBindCurrentUser {
		targetUserID, err := h.readOAuthBindUserIDFromCookie(c, feishuOAuthBindUserCookieName)
		if err != nil {
			redirectOAuthError(c, frontendCallback, "invalid_state", "invalid bind user cookie", "")
			return
		}
		resolvedEmail := strings.TrimSpace(profile.Email)
		if resolvedEmail == "" {
			resolvedEmail = buildFeishuSyntheticEmail(subject)
		}
		sessionToken, err := h.createOAuthPendingSessionWithToken(c, oauthPendingSessionPayload{
			Intent: oauthIntentBindCurrentUser, Identity: identityKey,
			TargetUserID: &targetUserID, ResolvedEmail: resolvedEmail,
			RedirectTo: redirectTo, BrowserSessionKey: browserSessionKey,
			UpstreamIdentityClaims: upstreamClaims,
			CompletionResponse:     map[string]any{"redirect": redirectTo},
		})
		if err != nil {
			redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
			return
		}
		clearFeishuCookie(c, feishuOAuthBindUserCookieName, secureCookie)
		if qrTicketID != "" {
			_ = feishuQRStore.MarkConfirmedWithSession(c.Request.Context(), qrTicketID, "", redirectTo, sessionToken)
		}
		redirectToFrontendCallbackWithToken(c, frontendCallback, sessionToken)
		return
	}

	if existing, _ := h.findOAuthIdentityUser(c.Request.Context(), identityKey); existing != nil {
		sessionToken, err := h.createOAuthPendingSessionWithToken(c, oauthPendingSessionPayload{
			Intent: oauthIntentLogin, Identity: identityKey, TargetUserID: &existing.ID,
			ResolvedEmail: existing.Email, RedirectTo: redirectTo, BrowserSessionKey: browserSessionKey,
			UpstreamIdentityClaims: upstreamClaims,
			CompletionResponse:     map[string]any{"redirect": redirectTo},
		})
		if err != nil {
			redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
			return
		}
		if qrTicketID != "" {
			_ = feishuQRStore.MarkConfirmedWithSession(c.Request.Context(), qrTicketID, "", redirectTo, sessionToken)
		}
		redirectToFrontendCallbackWithToken(c, frontendCallback, sessionToken)
		return
	}

	signupBlocked := h.isFeishuSignupBlocked(c.Request.Context(), cfg)
	sessionToken, err := h.createFeishuDirectLoginPendingSession(c, identityKey, subject, redirectTo, browserSessionKey, upstreamClaims, profile, signupBlocked)
	if err != nil {
		redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
		return
	}
	if qrTicketID != "" {
		_ = feishuQRStore.MarkConfirmedWithSession(c.Request.Context(), qrTicketID, "", redirectTo, sessionToken)
	}
	redirectToFrontendCallbackWithToken(c, frontendCallback, sessionToken)
}

func (h *AuthHandler) createFeishuDirectLoginPendingSession(
	c *gin.Context,
	identity service.PendingAuthIdentityKey,
	subject string,
	redirectTo string,
	browserSessionKey string,
	upstreamClaims map[string]any,
	profile *feishuOAuthProfile,
	signupBlocked bool,
) (string, error) {
	if signupBlocked {
		return "", service.ErrRegDisabled
	}

	email := strings.TrimSpace(profile.Email)
	if email == "" {
		email = buildFeishuSyntheticEmail(subject)
	}
	username := feishuUsernameFromEmail(email)
	if username == "" {
		username = strings.TrimSpace(profile.Name)
	}
	if username == "" {
		username = "feishu-" + strings.TrimSpace(subject)
	}

	_, user, err := h.authService.LoginOrRegisterOAuthWithTokenPair(c.Request.Context(), email, username, "", "", "feishu")
	if err != nil {
		return "", err
	}
	if user == nil || user.ID <= 0 {
		return "", infraerrors.InternalServer("FEISHU_DIRECT_LOGIN_FAILED", "failed to create feishu login user")
	}
	if err := h.ensureFeishuRuntimeIdentityBinding(c.Request.Context(), user.ID, identity, upstreamClaims); err != nil {
		return "", err
	}

	return h.createOAuthPendingSessionWithToken(c, oauthPendingSessionPayload{
		Intent:                 oauthIntentLogin,
		Identity:               identity,
		TargetUserID:           &user.ID,
		ResolvedEmail:          user.Email,
		RedirectTo:             redirectTo,
		BrowserSessionKey:      browserSessionKey,
		UpstreamIdentityClaims: upstreamClaims,
		CompletionResponse:     map[string]any{"redirect": redirectTo},
	})
}

func buildFeishuAuthorizeURL(cfg config.FeishuConnectConfig, state string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.AuthorizeURL))
	if err != nil {
		return "", infraerrors.InternalServer("FEISHU_AUTHORIZE_URL_PARSE_FAILED", "failed to parse feishu authorize_url").WithCause(err)
	}
	q := u.Query()
	q.Set("client_id", strings.TrimSpace(cfg.ClientID))
	q.Set("response_type", "code")
	q.Set("redirect_uri", strings.TrimSpace(cfg.RedirectURL))
	q.Set("state", state)
	if scopes := strings.TrimSpace(cfg.Scopes); scopes != "" {
		q.Set("scope", scopes)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (h *AuthHandler) prepareFeishuOAuthSession(c *gin.Context) (*feishuOAuthPreparedSession, error) {
	cfg, err := h.getFeishuOAuthConfig(c.Request.Context())
	if err != nil {
		return nil, err
	}
	state, err := oauth.GenerateState()
	if err != nil {
		return nil, infraerrors.InternalServer("OAUTH_STATE_GEN_FAILED", "failed to generate oauth state").WithCause(err)
	}
	redirectTo := sanitizeFrontendRedirectPath(c.Query("redirect"))
	if redirectTo == "" {
		redirectTo = feishuOAuthDefaultRedirectTo
	}
	browserSessionKey, err := generateOAuthPendingBrowserSession()
	if err != nil {
		return nil, infraerrors.InternalServer("OAUTH_BROWSER_SESSION_GEN_FAILED", "failed to generate oauth browser session").WithCause(err)
	}
	intent := normalizeOAuthIntent(c.Query("intent"))
	selectedTenantKey, err := resolveSelectedFeishuTenantKey(cfg, c.Query("tenant_key"))
	if err != nil {
		return nil, err
	}
	cfg = applySelectedFeishuTenantConfig(cfg, selectedTenantKey)
	secureCookie := isRequestHTTPS(c)
	setFeishuCookie(c, feishuOAuthStateCookieName, encodeCookieValue(state), feishuOAuthCookieMaxAgeSec, secureCookie)
	setFeishuCookie(c, feishuOAuthRedirectCookie, encodeCookieValue(redirectTo), feishuOAuthCookieMaxAgeSec, secureCookie)
	setFeishuCookie(c, feishuOAuthIntentCookieName, encodeCookieValue(intent), feishuOAuthCookieMaxAgeSec, secureCookie)
	setOAuthPendingBrowserCookie(c, browserSessionKey, secureCookie)
	clearOAuthPendingSessionCookie(c, secureCookie)
	if intent == oauthIntentBindCurrentUser {
		bindCookieValue, err := h.buildOAuthBindUserCookieFromContext(c)
		if err != nil {
			return nil, err
		}
		setFeishuCookie(c, feishuOAuthBindUserCookieName, encodeCookieValue(bindCookieValue), feishuOAuthCookieMaxAgeSec, secureCookie)
	} else {
		clearFeishuCookie(c, feishuOAuthBindUserCookieName, secureCookie)
	}
	return &feishuOAuthPreparedSession{
		cfg:               cfg,
		state:             state,
		redirectTo:        redirectTo,
		intent:            intent,
		browserSessionKey: browserSessionKey,
		selectedTenantKey: selectedTenantKey,
	}, nil
}

func (c *feishuOAuthClient) FetchProfile(ctx context.Context, code string) (*feishuOAuthProfile, error) {
	appToken, err := c.fetchAppAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	userToken, err := c.exchangeCode(ctx, appToken, code)
	if err != nil {
		return nil, err
	}
	return c.fetchUserInfo(ctx, userToken)
}

func (c *feishuOAuthClient) fetchAppAccessToken(ctx context.Context) (string, error) {
	body := map[string]string{"app_id": strings.TrimSpace(c.cfg.ClientID), "app_secret": strings.TrimSpace(c.cfg.ClientSecret)}
	raw, err := c.doJSON(ctx, http.MethodPost, c.cfg.AppAccessTokenURL, "", body)
	if err != nil {
		return "", err
	}
	token := feishuString(raw, "app_access_token", "tenant_access_token")
	if token == "" {
		return "", infraerrors.InternalServer("FEISHU_APP_TOKEN_FAILED", "feishu app access token missing")
	}
	return token, nil
}

func (c *feishuOAuthClient) exchangeCode(ctx context.Context, appAccessToken, code string) (string, error) {
	body := map[string]string{"grant_type": "authorization_code", "code": strings.TrimSpace(code)}
	raw, err := c.doJSON(ctx, http.MethodPost, c.cfg.TokenURL, appAccessToken, body)
	if err != nil {
		return "", err
	}
	token := feishuString(raw, "access_token", "user_access_token")
	if token == "" {
		return "", infraerrors.InternalServer("FEISHU_TOKEN_EXCHANGE_FAILED", "feishu user access token missing")
	}
	return token, nil
}

func (c *feishuOAuthClient) fetchUserInfo(ctx context.Context, userAccessToken string) (*feishuOAuthProfile, error) {
	raw, err := c.doJSON(ctx, http.MethodGet, c.cfg.UserInfoURL, userAccessToken, nil)
	if err != nil {
		return nil, err
	}
	profile := &feishuOAuthProfile{
		OpenID:    feishuString(raw, "open_id", "openId"),
		UnionID:   feishuString(raw, "union_id", "unionId"),
		TenantKey: feishuString(raw, "tenant_key"),
		Email:     strings.TrimSpace(strings.ToLower(feishuString(raw, "email", "enterprise_email", "corp_email"))),
		Name:      feishuString(raw, "name", "en_name"),
		AvatarURL: feishuString(raw, "avatar_url", "avatar_thumb"),
		Raw:       raw,
	}
	return profile, nil
}

func buildFeishuQRPageURL(region, gotoURL string) string {
	u := url.URL{Path: "/api/v1/auth/oauth/feishu/qr/page"}
	q := u.Query()
	q.Set("goto", gotoURL)
	if strings.TrimSpace(region) != "" {
		q.Set("region", strings.TrimSpace(region))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func feishuQRSDKURL(region string) string {
	if strings.EqualFold(strings.TrimSpace(region), "int") {
		return "https://lf-package-va.larksuitecdn.com/obj/lark-static-us/lark/passport/qrcode/LarkSSOSDKWebQRCode-1.0.3.js"
	}
	return "https://lf-package-cn.feishucdn.com/obj/feishu-static/lark/passport/qrcode/LarkSSOSDKWebQRCode-1.0.3.js"
}

func isAllowedFeishuAuthorizeURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" {
		return false
	}
	switch strings.ToLower(u.Host) {
	case "passport.feishu.cn", "accounts.feishu.cn", "passport.larksuite.com", "accounts.larksuite.com":
		return strings.Contains(u.Path, "/oauth/") || strings.Contains(u.Path, "/oauth2/")
	default:
		return false
	}
}

func (c *feishuOAuthClient) doJSON(ctx context.Context, method, endpoint, bearer string, payload any) (map[string]any, error) {
	var body io.Reader
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSpace(endpoint), body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(bearer) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearer))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, infraerrors.InternalServer("FEISHU_UPSTREAM_HTTP_ERROR", fmt.Sprintf("feishu upstream http status %d", resp.StatusCode))
	}
	var decoded map[string]any
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return nil, infraerrors.InternalServer("FEISHU_UPSTREAM_DECODE_FAILED", "failed to decode feishu upstream response").WithCause(err)
	}
	if code := feishuCode(decoded); code != "" && code != "0" {
		return nil, infraerrors.InternalServer("FEISHU_UPSTREAM_ERROR", "feishu upstream error: "+code+" "+feishuString(decoded, "msg", "message"))
	}
	if data, ok := decoded["data"].(map[string]any); ok {
		return data, nil
	}
	return decoded, nil
}

func feishuCode(raw map[string]any) string {
	switch v := raw["code"].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	default:
		return ""
	}
}

func feishuString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := raw[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func buildFeishuSyntheticEmail(subject string) string {
	return "feishu-" + strings.ToLower(strings.TrimSpace(subject)) + service.FeishuConnectSyntheticEmailDomain
}

func feishuUsernameFromEmail(email string) string {
	local, _, ok := strings.Cut(strings.TrimSpace(email), "@")
	if !ok {
		return ""
	}
	local = strings.TrimSpace(local)
	if local == "" || strings.HasPrefix(strings.ToLower(email), "feishu-") && strings.HasSuffix(strings.ToLower(email), service.FeishuConnectSyntheticEmailDomain) {
		return ""
	}
	if len(local) > 100 {
		return local[:100]
	}
	return local
}

func buildFeishuUpstreamClaims(profile *feishuOAuthProfile) map[string]any {
	claims := map[string]any{
		"email":      strings.TrimSpace(profile.Email),
		"username":   strings.TrimSpace(profile.Name),
		"subject":    firstNonEmpty(profile.UnionID, profile.OpenID),
		"open_id":    strings.TrimSpace(profile.OpenID),
		"union_id":   strings.TrimSpace(profile.UnionID),
		"tenant_key": strings.TrimSpace(profile.TenantKey),
	}
	if strings.TrimSpace(profile.AvatarURL) != "" {
		claims["suggested_avatar_url"] = strings.TrimSpace(profile.AvatarURL)
	}
	if strings.TrimSpace(profile.Name) != "" {
		claims["suggested_display_name"] = strings.TrimSpace(profile.Name)
	}
	return claims
}

func checkFeishuTenantAllowed(cfg config.FeishuConnectConfig, tenantKey string) bool {
	tenantKey = strings.TrimSpace(tenantKey)
	if tenantKey == "" {
		return false
	}
	return findFeishuTenantOption(cfg, tenantKey) != nil
}

func resolveSelectedFeishuTenantKey(cfg config.FeishuConnectConfig, rawTenantKey string) (string, error) {
	if len(cfg.TenantOptions) == 0 {
		return "", infraerrors.BadRequest("FEISHU_TENANT_REQUIRED", "feishu tenant options are not configured")
	}
	tenantKey := strings.TrimSpace(rawTenantKey)
	if tenantKey == "" {
		if len(cfg.TenantOptions) == 1 {
			return strings.TrimSpace(cfg.TenantOptions[0].TenantKey), nil
		}
		return "", infraerrors.BadRequest("FEISHU_TENANT_REQUIRED", "feishu tenant_key is required")
	}
	if findFeishuTenantOption(cfg, tenantKey) == nil {
		return "", infraerrors.BadRequest("FEISHU_TENANT_INVALID", "feishu tenant_key is not configured")
	}
	return tenantKey, nil
}

func findFeishuTenantOption(cfg config.FeishuConnectConfig, tenantKey string) *config.FeishuTenantOptionConfig {
	tenantKey = strings.TrimSpace(tenantKey)
	if tenantKey == "" {
		return nil
	}
	for i := range cfg.TenantOptions {
		if strings.TrimSpace(cfg.TenantOptions[i].TenantKey) == tenantKey {
			return &cfg.TenantOptions[i]
		}
	}
	return nil
}

func applySelectedFeishuTenantConfig(cfg config.FeishuConnectConfig, selectedTenantKey string) config.FeishuConnectConfig {
	option := findFeishuTenantOption(cfg, selectedTenantKey)
	if option == nil {
		return cfg
	}
	if clientID := strings.TrimSpace(option.ClientID); clientID != "" {
		cfg.ClientID = clientID
	}
	if clientSecret := strings.TrimSpace(option.ClientSecret); clientSecret != "" {
		cfg.ClientSecret = clientSecret
	}
	return cfg
}

func feishuTenantOptionLogValues(cfg config.FeishuConnectConfig) []map[string]any {
	options := make([]map[string]any, 0, len(cfg.TenantOptions))
	for _, option := range cfg.TenantOptions {
		options = append(options, map[string]any{
			"name":                     strings.TrimSpace(option.Name),
			"tenant_key":               strings.TrimSpace(option.TenantKey),
			"client_id":                strings.TrimSpace(option.ClientID),
			"client_secret_configured": strings.TrimSpace(option.ClientSecret) != "",
			"group_id":                 option.GroupID,
		})
	}
	return options
}

func (h *AuthHandler) ensureFeishuRuntimeIdentityBinding(
	ctx context.Context,
	userID int64,
	identity service.PendingAuthIdentityKey,
	upstreamClaims map[string]any,
) error {
	client := h.entClient()
	if client == nil {
		return infraerrors.ServiceUnavailable("PENDING_AUTH_NOT_READY", "pending auth service is not ready")
	}

	tx, err := client.Tx(ctx)
	if err != nil {
		return infraerrors.InternalServer("AUTH_IDENTITY_BIND_FAILED", "failed to begin feishu identity binding transaction").WithCause(err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = ensurePendingOAuthIdentityForUser(dbent.NewTxContext(ctx, tx), tx, &dbent.PendingAuthSession{
		ProviderType:           strings.TrimSpace(identity.ProviderType),
		ProviderKey:            strings.TrimSpace(identity.ProviderKey),
		ProviderSubject:        strings.TrimSpace(identity.ProviderSubject),
		UpstreamIdentityClaims: cloneOAuthMetadata(upstreamClaims),
	}, userID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (h *AuthHandler) isFeishuSignupBlocked(ctx context.Context, cfg config.FeishuConnectConfig) bool {
	if h == nil || h.settingSvc == nil {
		return false
	}
	if h.settingSvc.IsRegistrationEnabled(ctx) {
		return false
	}
	if cfg.BypassRegistration {
		return false
	}
	return true
}

// completeFeishuOAuthRegistration 是飞书邀请码注册和新账户创建的统一入口。
// 对应路由：
//   - POST /api/v1/auth/oauth/feishu/complete-registration（邀请码注册）
//   - POST /api/v1/auth/oauth/feishu/create-account（新账户创建）
func (h *AuthHandler) completeFeishuOAuthRegistration(c *gin.Context) {
	h.createPendingOAuthAccount(c, "feishu")
}

func (h *AuthHandler) CreateFeishuOAuthAccount(c *gin.Context) { h.completeFeishuOAuthRegistration(c) }
func (h *AuthHandler) CompleteFeishuOAuthRegistration(c *gin.Context) {
	h.completeFeishuOAuthRegistration(c)
}
func (h *AuthHandler) BindFeishuOAuthLogin(c *gin.Context) { h.bindPendingOAuthLogin(c, "feishu") }
