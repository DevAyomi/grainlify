package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/jagadeesh/grainlify/backend/internal/auth"
	"github.com/jagadeesh/grainlify/backend/internal/config"
	"github.com/jagadeesh/grainlify/backend/internal/cryptox"
	"github.com/jagadeesh/grainlify/backend/internal/db"
	"github.com/jagadeesh/grainlify/backend/internal/github"
)

// isAllowedRedirectURI validates that a redirect URI is from an allowed origin.
// This prevents open redirect vulnerabilities by only allowing:
// - localhost origins (for development)
// - *.vercel.app domains (for preview deployments)
// - Explicit origins from CORS_ORIGINS config
// - FrontendBaseURL (if configured)
func isAllowedRedirectURI(redirectURI string, cfg config.Config) bool {
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}

	// Extract origin (scheme + host)
	origin := parsedURL.Scheme + "://" + parsedURL.Host

	// Always allow localhost origins for development
	if strings.HasPrefix(origin, "http://localhost:") ||
		strings.HasPrefix(origin, "http://127.0.0.1:") ||
		strings.HasPrefix(origin, "https://localhost:") ||
		strings.HasPrefix(origin, "https://127.0.0.1:") {
		return true
	}

	// Allow all Vercel preview deployments (*.vercel.app)
	if strings.HasSuffix(origin, ".vercel.app") {
		return true
	}

	// Check explicit CORS origins
	if strings.TrimSpace(cfg.CORSOrigins) != "" {
		for _, o := range strings.Split(cfg.CORSOrigins, ",") {
			o = strings.TrimSpace(o)
			if o == "" {
				continue
			}
			if origin == o || strings.HasPrefix(origin, o+"/") {
				return true
			}
		}
	}

	// If FrontendBaseURL is set, allow it
	if cfg.FrontendBaseURL != "" {
		if origin == cfg.FrontendBaseURL || strings.HasPrefix(origin, cfg.FrontendBaseURL+"/") {
			return true
		}
	}

	return false
}

type GitHubOAuthHandler struct {
	cfg config.Config
	db  *db.DB
}

func NewGitHubOAuthHandler(cfg config.Config, d *db.DB) *GitHubOAuthHandler {
	return &GitHubOAuthHandler{cfg: cfg, db: d}
}

func (h *GitHubOAuthHandler) Start() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}
		if h.cfg.GitHubOAuthClientID == "" || effectiveGitHubRedirect(h.cfg) == "" {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "github_oauth_not_configured"})
		}

		sub, _ := c.Locals(auth.LocalUserID).(string)
		userID, err := uuid.Parse(sub)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_user"})
		}

		state := randomState(32)
		expiresAt := time.Now().UTC().Add(10 * time.Minute)

		_, err = h.db.Pool.Exec(c.Context(), `
INSERT INTO oauth_states (state, user_id, kind, expires_at)
VALUES ($1, $2, 'github_link', $3)
`, state, userID, expiresAt)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "state_create_failed"})
		}

		// Scopes:
		// - read:user: link identity
		// - user:email: access user email addresses
		// - repo: access private repos + read repo metadata
		// - admin:repo_hook: create webhooks
		// - read:org: helps when dealing with org-owned repos
		authURL, err := github.AuthorizeURL(h.cfg.GitHubOAuthClientID, effectiveGitHubRedirect(h.cfg), state, []string{"read:user", "user:email", "repo", "admin:repo_hook", "read:org"})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "auth_url_failed"})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{"url": authURL})
	}
}

// LoginStart begins GitHub-only login/signup (no prior JWT required).
// Accepts optional 'redirect' query parameter to specify where to redirect after successful login.
// This enables single OAuth callback URL to work with multiple frontend deployments (production, preview, etc.)
func (h *GitHubOAuthHandler) LoginStart() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}
		if h.cfg.GitHubOAuthClientID == "" || effectiveGitHubRedirect(h.cfg) == "" {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "github_login_not_configured"})
		}

		// Get redirect_uri from query parameter (frontend origin)
		redirectURI := c.Query("redirect")
		slog.Info("OAuth login start - received redirect parameter", "redirect", redirectURI)
		
		// Validate redirect_uri is a valid URL and from an allowed origin
		if redirectURI != "" {
			parsedURL, err := url.Parse(redirectURI)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_redirect_uri"})
			}

			// Security: Only allow redirects to whitelisted origins
			// This prevents open redirect vulnerabilities
			if !isAllowedRedirectURI(redirectURI, h.cfg) {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   "redirect_uri_not_allowed",
					"message": "Redirect URI must be from an allowed origin (localhost, *.vercel.app, or configured CORS origins)",
				})
			}

			// Ensure redirect URI uses http or https scheme
			if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_redirect_uri_scheme"})
			}
		}

		state := randomState(32)
		expiresAt := time.Now().UTC().Add(10 * time.Minute)

		// Store redirect_uri in oauth_states table for later use in callback
		_, err := h.db.Pool.Exec(c.Context(), `
INSERT INTO oauth_states (state, user_id, kind, expires_at, redirect_uri)
VALUES ($1, NULL, 'github_login', $2, $3)
`, state, expiresAt, redirectURI)
		if err != nil {
			slog.Error("OAuth login start - failed to store state", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "state_create_failed"})
		}
		slog.Info("OAuth login start - stored redirect_uri in state", "redirect_uri", redirectURI, "state", state)

		// Login scopes: identity + email + repo access for later project verification.
		authURL, err := github.AuthorizeURL(h.cfg.GitHubOAuthClientID, effectiveGitHubRedirect(h.cfg), state, []string{"read:user", "user:email", "repo", "admin:repo_hook", "read:org"})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "auth_url_failed"})
		}

		// Redirect user to GitHub OAuth page
		return c.Redirect(authURL, fiber.StatusFound)
	}
}

// CallbackUnified finishes either:
// - github_login: GitHub-only login/signup (issues JWT)
// - github_link: link/re-authorize GitHub for an existing user
//
// Recommended for production: configure ONE GitHub OAuth callback URL and point it to this handler.
func (h *GitHubOAuthHandler) CallbackUnified() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}
		if h.cfg.GitHubOAuthClientID == "" || h.cfg.GitHubOAuthClientSecret == "" || effectiveGitHubRedirect(h.cfg) == "" {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "github_oauth_not_configured"})
		}
		if h.cfg.JWTSecret == "" {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "jwt_not_configured"})
		}

		code := c.Query("code")
		state := c.Query("state")
		if code == "" || state == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing_code_or_state"})
		}

		var storedKind string
		var stateUserID *uuid.UUID
		var storedRedirectURI *string
		err := h.db.Pool.QueryRow(c.Context(), `
SELECT kind, user_id, redirect_uri
FROM oauth_states
WHERE state = $1
  AND expires_at > now()
`, state).Scan(&storedKind, &stateUserID, &storedRedirectURI)
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_or_expired_state"})
		}
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "state_lookup_failed"})
		}

		// Log the retrieved redirect_uri for debugging
		if storedRedirectURI != nil && *storedRedirectURI != "" {
			slog.Info("OAuth callback - retrieved redirect_uri from state",
				"redirect_uri", *storedRedirectURI,
				"kind", storedKind,
			)
		} else {
			slog.Info("OAuth callback - no redirect_uri in state, will use fallback",
				"kind", storedKind,
			)
		}

		_, _ = h.db.Pool.Exec(c.Context(), `DELETE FROM oauth_states WHERE state = $1`, state)

		tr, err := github.ExchangeCode(c.Context(), code, github.OAuthConfig{
			ClientID:     h.cfg.GitHubOAuthClientID,
			ClientSecret: h.cfg.GitHubOAuthClientSecret,
			RedirectURL:  effectiveGitHubRedirect(h.cfg),
		})
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token_exchange_failed"})
		}

		encKey, err := cryptox.KeyFromB64(h.cfg.TokenEncKeyB64)
		if err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "token_encryption_not_configured"})
		}
		encToken, err := cryptox.EncryptAESGCM(encKey, []byte(tr.AccessToken))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token_encrypt_failed"})
		}

		gh := github.NewClient()
		u, err := gh.GetUser(c.Context(), tr.AccessToken)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "github_user_fetch_failed"})
		}

		var userID uuid.UUID
		var role string
		switch storedKind {
		case "github_login":
			// Create-or-find user by github_user_id.
			err = h.db.Pool.QueryRow(c.Context(), `
SELECT id, role
FROM users
WHERE github_user_id = $1
`, u.ID).Scan(&userID, &role)
			if errors.Is(err, pgx.ErrNoRows) {
				err = h.db.Pool.QueryRow(c.Context(), `
INSERT INTO users (github_user_id) VALUES ($1)
RETURNING id, role
`, u.ID).Scan(&userID, &role)
			}
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user_upsert_failed"})
			}
		case "github_link":
			if stateUserID == nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_state_user"})
			}
			userID = *stateUserID
			// Fetch role for JWT issuance.
			if err := h.db.Pool.QueryRow(c.Context(), `SELECT role FROM users WHERE id = $1`, userID).Scan(&role); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user_lookup_failed"})
			}
		default:
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "wrong_state_kind"})
		}

		_, err = h.db.Pool.Exec(c.Context(), `
INSERT INTO github_accounts (user_id, github_user_id, login, avatar_url, access_token, token_type, scope)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (user_id) DO UPDATE SET
  github_user_id = EXCLUDED.github_user_id,
  login = EXCLUDED.login,
  avatar_url = EXCLUDED.avatar_url,
  access_token = EXCLUDED.access_token,
  token_type = EXCLUDED.token_type,
  scope = EXCLUDED.scope,
  updated_at = now()
`, userID, u.ID, u.Login, u.AvatarURL, encToken, tr.TokenType, tr.Scope)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "github_account_upsert_failed"})
		}

		// Ensure users.github_user_id is set (idempotent).
		_, _ = h.db.Pool.Exec(c.Context(), `
UPDATE users SET github_user_id = $2, updated_at = now() WHERE id = $1
`, userID, u.ID)

		// For login: issue JWT. For link: we can optionally redirect without token.
		if storedKind == "github_login" {
			jwtToken, err := auth.IssueJWT(h.cfg.JWTSecret, userID, role, "", "", 60*time.Minute)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token_issue_failed"})
			}

			// Determine redirect URL priority:
			// 1. Stored redirect_uri from frontend (enables multi-environment support)
			// 2. Config GitHubLoginSuccessRedirectURL
			// 3. Construct from FrontendBaseURL
			// IMPORTANT: Always redirect to override GitHub's Homepage URL default
			var redirectURL string
			if storedRedirectURI != nil && *storedRedirectURI != "" {
				// Use the redirect_uri provided by the frontend (supports preview deployments, forks, etc.)
				redirectURL = strings.TrimSuffix(*storedRedirectURI, "/") + "/auth/callback"
				slog.Info("OAuth redirect - using stored redirect_uri", "redirect_url", redirectURL)
			} else if h.cfg.GitHubLoginSuccessRedirectURL != "" {
				// If GitHubLoginSuccessRedirectURL doesn't already include /auth/callback, append it
				redirectURL = strings.TrimSuffix(h.cfg.GitHubLoginSuccessRedirectURL, "/")
				if !strings.HasSuffix(redirectURL, "/auth/callback") {
					redirectURL = redirectURL + "/auth/callback"
				}
				slog.Info("OAuth redirect - using GitHubLoginSuccessRedirectURL", "redirect_url", redirectURL)
			} else if h.cfg.FrontendBaseURL != "" {
				redirectURL = strings.TrimSuffix(h.cfg.FrontendBaseURL, "/") + "/auth/callback"
				slog.Info("OAuth redirect - using FrontendBaseURL", "redirect_url", redirectURL)
			} else {
				slog.Warn("OAuth redirect - no redirect URL configured, cannot redirect user")
			}

			// Always redirect if we have a URL (this overrides GitHub's Homepage URL)
			if redirectURL != "" {
				ru, err := url.Parse(redirectURL)
				if err != nil {
					slog.Error("OAuth redirect - failed to parse redirect URL", "error", err, "redirect_url", redirectURL)
					// Fall through to JSON response
				} else {
					// Ensure the path is set correctly (should be /auth/callback)
					if ru.Path == "" || ru.Path == "/" {
						ru.Path = "/auth/callback"
					}
					q := ru.Query()
					q.Set("token", jwtToken)
					q.Set("github", u.Login)
					ru.RawQuery = q.Encode()
					finalRedirectURL := ru.String()
					slog.Info("OAuth redirect - redirecting user", 
						"final_redirect_url", finalRedirectURL,
						"path", ru.Path,
						"host", ru.Host,
					)
					return c.Redirect(finalRedirectURL, fiber.StatusFound)
				}
			}

			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"token": jwtToken,
				"user": fiber.Map{
					"id":   userID.String(),
					"role": role,
				},
				"github": fiber.Map{
					"id":         u.ID,
					"login":      u.Login,
					"avatar_url": u.AvatarURL,
				},
			})
		}

		// github_link behavior (no new token required).
		if h.cfg.GitHubOAuthSuccessRedirectURL != "" {
			ru, err := url.Parse(h.cfg.GitHubOAuthSuccessRedirectURL)
			if err == nil {
				q := ru.Query()
				q.Set("linked", "true")
				q.Set("github", u.Login)
				ru.RawQuery = q.Encode()
				return c.Redirect(ru.String(), fiber.StatusFound)
			}
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"ok": true,
			"github": fiber.Map{
				"id":         u.ID,
				"login":      u.Login,
				"avatar_url": u.AvatarURL,
			},
		})
	}
}

func effectiveGitHubRedirect(cfg config.Config) string {
	// Recommended: set GITHUB_OAUTH_REDIRECT_URL to the full callback URL
	// Example: http://localhost:8080/auth/github/login/callback
	// This must match exactly what's registered in your GitHub OAuth app settings
	if strings.TrimSpace(cfg.GitHubOAuthRedirectURL) != "" {
		return strings.TrimSpace(cfg.GitHubOAuthRedirectURL)
	}
	// Fallback to GitHubLoginRedirectURL for backwards compatibility
	if strings.TrimSpace(cfg.GitHubLoginRedirectURL) != "" {
		return strings.TrimSpace(cfg.GitHubLoginRedirectURL)
	}
	// If neither is set and we have PublicBaseURL, construct it
	if cfg.PublicBaseURL != "" {
		baseURL := strings.TrimSuffix(cfg.PublicBaseURL, "/")
		return baseURL + "/auth/github/login/callback"
	}
	return ""
}

func (h *GitHubOAuthHandler) Status() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}

		sub, _ := c.Locals(auth.LocalUserID).(string)
		userID, err := uuid.Parse(sub)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_user"})
		}

		var githubUserID int64
		var login string
		var avatarURL *string
		err = h.db.Pool.QueryRow(c.Context(), `
SELECT github_user_id, login, avatar_url
FROM github_accounts
WHERE user_id = $1
`, userID).Scan(&githubUserID, &login, &avatarURL)
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"linked": false,
			})
		}
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "status_failed"})
		}

		githubMap := fiber.Map{
			"id":    githubUserID,
			"login": login,
		}
		if avatarURL != nil && *avatarURL != "" {
			githubMap["avatar_url"] = *avatarURL
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"linked": true,
			"github": githubMap,
		})
	}
}

func randomState(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}


