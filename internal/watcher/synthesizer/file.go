package synthesizer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/geminicli"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// FileSynthesizer generates Auth entries from OAuth JSON files.
// It handles file-based authentication and Gemini virtual auth generation.
type FileSynthesizer struct{}

// NewFileSynthesizer creates a new FileSynthesizer instance.
func NewFileSynthesizer() *FileSynthesizer {
	return &FileSynthesizer{}
}

// Synthesize generates Auth entries from auth files in the auth directory.
func (s *FileSynthesizer) Synthesize(ctx *SynthesisContext) ([]*coreauth.Auth, error) {
	out := make([]*coreauth.Auth, 0, 16)
	if ctx == nil || ctx.AuthDir == "" {
		return out, nil
	}

	entries, err := os.ReadDir(ctx.AuthDir)
	if err != nil {
		// Not an error if directory doesn't exist
		return out, nil
	}

	now := ctx.Now
	cfg := ctx.Config

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		full := filepath.Join(ctx.AuthDir, name)
		data, errRead := os.ReadFile(full)
		if errRead != nil || len(data) == 0 {
			continue
		}
		var metadata map[string]any
		if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
			continue
		}
		t, _ := metadata["type"].(string)
		if t == "" {
			continue
		}
		provider := strings.ToLower(t)
		if provider == "gemini" {
			provider = "gemini-cli"
		}
		label := provider
		if email, _ := metadata["email"].(string); email != "" {
			label = email
		}
		// Use relative path under authDir as ID to stay consistent with the file-based token store
		id := full
		if rel, errRel := filepath.Rel(ctx.AuthDir, full); errRel == nil && rel != "" {
			id = rel
		}

		proxyURL := ""
		if p, ok := metadata["proxy_url"].(string); ok {
			proxyURL = p
		}

		prefix := ""
		if rawPrefix, ok := metadata["prefix"].(string); ok {
			trimmed := strings.TrimSpace(rawPrefix)
			trimmed = strings.Trim(trimmed, "/")
			if trimmed != "" && !strings.Contains(trimmed, "/") {
				prefix = trimmed
			}
		}

		a := &coreauth.Auth{
			ID:       id,
			Provider: provider,
			Label:    label,
			Prefix:   prefix,
			Status:   coreauth.StatusActive,
			Attributes: map[string]string{
				"source": full,
				"path":   full,
			},
			ProxyURL:  proxyURL,
			Metadata:  metadata,
			CreatedAt: now,
			UpdatedAt: now,
		}
		ApplyAuthExcludedModelsMeta(a, cfg, nil, "oauth")
		if provider == "gemini-cli" {
			if virtuals := SynthesizeGeminiVirtualAuths(a, metadata, now); len(virtuals) > 0 {
				for _, v := range virtuals {
					ApplyAuthExcludedModelsMeta(v, cfg, nil, "oauth")
				}
				out = append(out, a)
				out = append(out, virtuals...)
				continue
			}
		}
		if provider == "codex" {
			if virtuals := SynthesizeCodexVirtualAuths(a, metadata, now); len(virtuals) > 0 {
				for _, v := range virtuals {
					ApplyAuthExcludedModelsMeta(v, cfg, nil, "oauth")
				}
				out = append(out, a)
				out = append(out, virtuals...)
				continue
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// SynthesizeGeminiVirtualAuths creates virtual Auth entries for multi-project Gemini credentials.
// It disables the primary auth and creates one virtual auth per project.
func SynthesizeGeminiVirtualAuths(primary *coreauth.Auth, metadata map[string]any, now time.Time) []*coreauth.Auth {
	if primary == nil || metadata == nil {
		return nil
	}
	projects := splitGeminiProjectIDs(metadata)
	if len(projects) <= 1 {
		return nil
	}
	email, _ := metadata["email"].(string)
	shared := geminicli.NewSharedCredential(primary.ID, email, metadata, projects)
	primary.Disabled = true
	primary.Status = coreauth.StatusDisabled
	primary.Runtime = shared
	if primary.Attributes == nil {
		primary.Attributes = make(map[string]string)
	}
	primary.Attributes["gemini_virtual_primary"] = "true"
	primary.Attributes["virtual_children"] = strings.Join(projects, ",")
	source := primary.Attributes["source"]
	authPath := primary.Attributes["path"]
	originalProvider := primary.Provider
	if originalProvider == "" {
		originalProvider = "gemini-cli"
	}
	label := primary.Label
	if label == "" {
		label = originalProvider
	}
	virtuals := make([]*coreauth.Auth, 0, len(projects))
	for _, projectID := range projects {
		attrs := map[string]string{
			"runtime_only":           "true",
			"gemini_virtual_parent":  primary.ID,
			"gemini_virtual_project": projectID,
		}
		if source != "" {
			attrs["source"] = source
		}
		if authPath != "" {
			attrs["path"] = authPath
		}
		metadataCopy := map[string]any{
			"email":             email,
			"project_id":        projectID,
			"virtual":           true,
			"virtual_parent_id": primary.ID,
			"type":              metadata["type"],
		}
		proxy := strings.TrimSpace(primary.ProxyURL)
		if proxy != "" {
			metadataCopy["proxy_url"] = proxy
		}
		virtual := &coreauth.Auth{
			ID:         buildGeminiVirtualID(primary.ID, projectID),
			Provider:   originalProvider,
			Label:      fmt.Sprintf("%s [%s]", label, projectID),
			Status:     coreauth.StatusActive,
			Attributes: attrs,
			Metadata:   metadataCopy,
			ProxyURL:   primary.ProxyURL,
			Prefix:     primary.Prefix,
			CreatedAt:  primary.CreatedAt,
			UpdatedAt:  primary.UpdatedAt,
			Runtime:    geminicli.NewVirtualCredential(projectID, shared),
		}
		virtuals = append(virtuals, virtual)
	}
	return virtuals
}

type codexOrganization struct {
	ID        string
	Title     string
	IsDefault bool
}

// SynthesizeCodexVirtualAuths creates virtual Auth entries for multi-organization Codex credentials.
// It disables the primary auth and creates one virtual auth per organization.
func SynthesizeCodexVirtualAuths(primary *coreauth.Auth, metadata map[string]any, now time.Time) []*coreauth.Auth {
	if primary == nil || metadata == nil {
		return nil
	}
	orgs := extractCodexOrganizations(metadata)
	if len(orgs) <= 1 {
		return nil
	}
	primary.Disabled = true
	primary.Status = coreauth.StatusDisabled
	primary.StatusMessage = "codex org virtualization"
	if primary.Attributes == nil {
		primary.Attributes = make(map[string]string)
	}
	primary.Attributes["codex_virtual_primary"] = "true"

	source := primary.Attributes["source"]
	authPath := primary.Attributes["path"]
	basePrefix := strings.TrimSpace(primary.Prefix)
	originalProvider := primary.Provider
	if originalProvider == "" {
		originalProvider = "codex"
	}
	label := primary.Label
	if label == "" {
		label = originalProvider
	}
	orgIDs := make([]string, 0, len(orgs))
	virtuals := make([]*coreauth.Auth, 0, len(orgs))
	for _, org := range orgs {
		if org.ID == "" {
			continue
		}
		orgIDs = append(orgIDs, org.ID)
		attrs := map[string]string{
			"runtime_only":         "true",
			"codex_virtual_parent": primary.ID,
			"codex_virtual_org":    org.ID,
		}
		if org.IsDefault {
			attrs["codex_org_default"] = "true"
		}
		if source != "" {
			attrs["source"] = source
		}
		if authPath != "" {
			attrs["path"] = authPath
		}
		attrs["header:OpenAI-Organization"] = org.ID

		prefix := buildCodexOrgPrefix(basePrefix, org.ID)
		metadataCopy := cloneMetadataMap(metadata)
		if metadataCopy == nil {
			metadataCopy = make(map[string]any)
		}
		metadataCopy["organization_id"] = org.ID
		if org.Title != "" {
			metadataCopy["organization_title"] = org.Title
		}
		if org.IsDefault {
			metadataCopy["organization_default"] = true
		}
		metadataCopy["virtual"] = true
		metadataCopy["virtual_parent_id"] = primary.ID
		if providerType, ok := metadata["type"]; ok {
			metadataCopy["type"] = providerType
		}

		display := org.Title
		if display == "" {
			display = org.ID
		}
		virtual := &coreauth.Auth{
			ID:         buildCodexVirtualID(primary.ID, org.ID),
			Provider:   originalProvider,
			Label:      fmt.Sprintf("%s [%s]", label, display),
			Status:     coreauth.StatusActive,
			Attributes: attrs,
			Metadata:   metadataCopy,
			ProxyURL:   primary.ProxyURL,
			Prefix:     prefix,
			CreatedAt:  primary.CreatedAt,
			UpdatedAt:  primary.UpdatedAt,
		}
		virtuals = append(virtuals, virtual)
	}
	primary.Attributes["virtual_children"] = strings.Join(orgIDs, ",")
	return virtuals
}

func extractCodexOrganizations(metadata map[string]any) []codexOrganization {
	if metadata == nil {
		return nil
	}
	raw, ok := metadata["organizations"]
	if !ok || raw == nil {
		return nil
	}

	seen := make(map[string]struct{})
	orgs := make([]codexOrganization, 0, 4)
	add := func(org codexOrganization) {
		org.ID = strings.TrimSpace(org.ID)
		if org.ID == "" {
			return
		}
		key := strings.ToLower(org.ID)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		orgs = append(orgs, org)
	}

	var items []any
	switch typed := raw.(type) {
	case []any:
		items = typed
	case []map[string]any:
		items = make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
	case []map[string]string:
		items = make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		if err := json.Unmarshal([]byte(typed), &items); err != nil {
			return nil
		}
	default:
		return nil
	}

	for _, item := range items {
		if org, ok := parseCodexOrganization(item); ok {
			add(org)
		}
	}
	if len(orgs) == 0 {
		return nil
	}
	sort.SliceStable(orgs, func(i, j int) bool {
		if orgs[i].IsDefault != orgs[j].IsDefault {
			return orgs[i].IsDefault
		}
		left := strings.ToLower(orgs[i].Title)
		right := strings.ToLower(orgs[j].Title)
		if left == right {
			return strings.ToLower(orgs[i].ID) < strings.ToLower(orgs[j].ID)
		}
		return left < right
	})
	return orgs
}

func parseCodexOrganization(item any) (codexOrganization, bool) {
	switch typed := item.(type) {
	case map[string]any:
		return codexOrganization{
			ID:        stringValue(typed["id"]),
			Title:     stringValue(typed["title"]),
			IsDefault: boolValue(typed["is_default"]),
		}, true
	case map[string]string:
		return codexOrganization{
			ID:        strings.TrimSpace(typed["id"]),
			Title:     strings.TrimSpace(typed["title"]),
			IsDefault: strings.EqualFold(strings.TrimSpace(typed["is_default"]), "true"),
		}, true
	default:
		return codexOrganization{}, false
	}
}

func buildCodexOrgPrefix(basePrefix, orgID string) string {
	base := sanitizeCodexPrefix(basePrefix)
	org := sanitizeCodexPrefix(orgID)
	if org == "" {
		return base
	}
	if base == "" {
		return org
	}
	return base + "-" + org
}

func sanitizeCodexPrefix(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_-")
}

func buildCodexVirtualID(baseID, orgID string) string {
	org := strings.TrimSpace(orgID)
	if org == "" {
		org = "org"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_", ":", "_")
	return fmt.Sprintf("%s::%s", baseID, replacer.Replace(org))
}

func cloneMetadataMap(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		out := make(map[string]any, len(metadata))
		for k, v := range metadata {
			out[k] = v
		}
		return out
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		out = make(map[string]any, len(metadata))
		for k, v := range metadata {
			out[k] = v
		}
	}
	return out
}

func stringValue(value any) string {
	if v, ok := value.(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func boolValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

// splitGeminiProjectIDs extracts and deduplicates project IDs from metadata.
func splitGeminiProjectIDs(metadata map[string]any) []string {
	raw, _ := metadata["project_id"].(string)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

// buildGeminiVirtualID constructs a virtual auth ID from base ID and project ID.
func buildGeminiVirtualID(baseID, projectID string) string {
	project := strings.TrimSpace(projectID)
	if project == "" {
		project = "project"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_")
	return fmt.Sprintf("%s::%s", baseID, replacer.Replace(project))
}
