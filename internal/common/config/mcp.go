package config

import (
	"time"

	"github.com/ifuryst/lol"

	"github.com/mcp-ecosystem/mcp-gateway/internal/common/cnst"
	"github.com/mcp-ecosystem/mcp-gateway/pkg/mcp"
)

type (
	// MCPServer represents the MCP server data structure
	MCPServer struct {
		Name      string    `json:"name" yaml:"name" gorm:"primaryKey"`
		Content   MCPConfig `json:"content" yaml:"content" gorm:"type:json"`
		CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
	}

	MCPConfig struct {
		Name       string            `json:"name" yaml:"name" gorm:"primaryKey"`
		Tenant     string            `json:"tenant"  yaml:"tenant" gorm:"index"`
		CreatedAt  time.Time         `json:"createdAt" yaml:"createdAt"`
		UpdatedAt  time.Time         `json:"updatedAt" yaml:"updatedAt"`
		DeletedAt  time.Time         `json:"deletedAt" yaml:"deletedAt"` // non-zero indicates that all information has been deleted
		Routers    []RouterConfig    `json:"routers" yaml:"routers" gorm:"type:json"`
		Servers    []ServerConfig    `json:"servers" yaml:"servers" gorm:"type:json"`
		Tools      []ToolConfig      `json:"tools" yaml:"tools" gorm:"type:json"`
		McpServers []MCPServerConfig `json:"mcpServers" yaml:"mcpServers" gorm:"type:json"` // proxy mcp servers
	}

	RouterConfig struct {
		Server string      `json:"server" yaml:"server"`
		Prefix string      `json:"prefix" yaml:"prefix"`
		CORS   *CORSConfig `json:"cors,omitempty" yaml:"cors,omitempty"`
	}

	CORSConfig struct {
		AllowOrigins     []string `json:"allowOrigins" yaml:"allowOrigins"`
		AllowMethods     []string `json:"allowMethods" yaml:"allowMethods"`
		AllowHeaders     []string `json:"allowHeaders" yaml:"allowHeaders"`
		ExposeHeaders    []string `json:"exposeHeaders" yaml:"exposeHeaders"`
		AllowCredentials bool     `json:"allowCredentials" yaml:"allowCredentials"`
	}

	ProxyConfig struct {
		Host string `json:"host" yaml:"host"`
		Port int    `json:"port" yaml:"port"`
		Type string `json:"type" yaml:"type"` // http, https, socks5
	}

	ServerConfig struct {
		Name         string            `json:"name" yaml:"name"`
		Description  string            `json:"description" yaml:"description"`
		AllowedTools []string          `json:"allowedTools" yaml:"allowedTools"`
		Config       map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
	}

	ToolConfig struct {
		Name         string            `json:"name" yaml:"name"`
		Description  string            `json:"description,omitempty" yaml:"description,omitempty"`
		Method       string            `json:"method" yaml:"method"`
		Endpoint     string            `json:"endpoint" yaml:"endpoint"`
		Proxy        *ProxyConfig      `json:"proxy,omitempty" yaml:"proxy,omitempty"`
		Headers      map[string]string `json:"headers" yaml:"headers"`
		Args         []ArgConfig       `json:"args" yaml:"args"`
		RequestBody  string            `json:"requestBody"  yaml:"requestBody"`
		ResponseBody string            `json:"responseBody" yaml:"responseBody"`
		InputSchema  map[string]any    `json:"inputSchema,omitempty" yaml:"inputSchema,omitempty"`
	}

	MCPServerConfig struct {
		Type         string                `json:"type" yaml:"type"`                           // sse, stdio and streamable-http
		Name         string                `json:"name" yaml:"name"`                           // server name
		Command      string                `json:"command,omitempty" yaml:"command,omitempty"` // for stdio
		Args         []string              `json:"args,omitempty" yaml:"args,omitempty"`       // for stdio
		Env          map[string]string     `json:"env,omitempty" yaml:"env,omitempty"`         // for stdio
		URL          string                `json:"url,omitempty" yaml:"url,omitempty"`         // for sse and streamable-http
		Policy       cnst.MCPStartupPolicy `json:"policy" yaml:"policy"`                       // onStart or onDemand
		Preinstalled bool                  `json:"preinstalled" yaml:"preinstalled"`           // whether to install this MCP server when mcp-gateway starts
	}

	ArgConfig struct {
		Name        string      `json:"name" yaml:"name"`
		Position    string      `json:"position" yaml:"position"` // header, query, path, body
		Required    bool        `json:"required" yaml:"required"`
		Type        string      `json:"type" yaml:"type"`
		Description string      `json:"description" yaml:"description"`
		Default     string      `json:"default" yaml:"default"`
		Items       ItemsConfig `json:"items,omitempty" yaml:"items,omitempty"`
	}

	ItemsConfig struct {
		Type string   `json:"type" yaml:"type"`
		Enum []string `json:"enum,omitempty" yaml:"enum,omitempty"`
	}

	// MCPConfigVersion represents a version of an MCP configuration
	MCPConfigVersion struct {
		Version    int             `json:"version" yaml:"version"`
		CreatedBy  string          `json:"created_by" yaml:"created_by"`
		CreatedAt  time.Time       `json:"created_at" yaml:"created_at"`
		ActionType cnst.ActionType `json:"action_type" yaml:"action_type"` // Create, Update, Delete, Revert
		Name       string          `json:"name" yaml:"name"`
		Tenant     string          `json:"tenant" yaml:"tenant"`
		Routers    string          `json:"routers" yaml:"routers"`
		Servers    string          `json:"servers" yaml:"servers"`
		Tools      string          `json:"tools" yaml:"tools"`
		McpServers string          `json:"mcp_servers" yaml:"mcp_servers"`
		IsActive   bool            `json:"is_active" yaml:"is_active"` // indicates if this version is currently active
		Hash       string          `json:"hash" yaml:"hash"`           // hash of the configuration content
	}
)

// ToToolSchema converts a ToolConfig to a ToolSchema
func (t *ToolConfig) ToToolSchema() mcp.ToolSchema {
	// Create properties map for input schema
	properties := make(map[string]any)
	required := make([]string, 0)
	for _, arg := range t.Args {
		property := map[string]any{
			"type":        arg.Type,
			"description": arg.Description,
		}

		if arg.Type == "array" {
			items := make(map[string]any)
			if len(arg.Items.Enum) > 0 {
				items["enum"] = lol.Union(arg.Items.Enum)
			} else {
				items["type"] = arg.Items.Type
			}
			property["items"] = items
		}

		properties[arg.Name] = property
		if arg.Required {
			required = append(required, arg.Name)
		}
	}

	// Merge with existing input schema if any
	if t.InputSchema != nil {
		for k, v := range t.InputSchema {
			properties[k] = v
		}
	}

	return mcp.ToolSchema{
		Name:        t.Name,
		Description: t.Description,
		InputSchema: mcp.ToolInputSchema{
			Type:       "object",
			Properties: properties,
			Required:   required,
		},
	}
}

// FromMCPConfigVersion creates a new MCPConfigVersion from an MCPConfig
func FromMCPConfigVersion(cfg *MCPConfig, version int, createdBy string, actionType cnst.ActionType) *MCPConfigVersion {
	return &MCPConfigVersion{
		Version:    version,
		CreatedBy:  createdBy,
		CreatedAt:  time.Now(),
		ActionType: actionType,
	}
}
