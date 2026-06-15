package main

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed static/*
var staticFiles embed.FS

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildTime    = "unknown"
)

type contextKey string

const (
	roleViewer      = "viewer"
	roleAdmin       = "admin"
	roleFake        = "fake"
	defaultPort     = "8080"
	defaultRotate   = time.Hour
	roleContextKey  = contextKey("role")
	labelKey        = "simple-docker-log.sensitivity"
	labelTrue       = "true"
	defaultTailLine = "200"
	fakeFailLimit   = 10
)

type session struct {
	Role     string
	IssuedAt time.Time
}

type authManager struct {
	enabled    bool
	interval   time.Duration
	mu         sync.RWMutex
	viewerPw   string
	adminPw    string
	tokens     map[string]session
	fakeTokens map[string]session
	failures   map[string]int
}

func newAuthManager(enabled bool, interval time.Duration) *authManager {
	am := &authManager{
		enabled:    enabled,
		interval:   interval,
		tokens:     make(map[string]session),
		fakeTokens: make(map[string]session),
		failures:   make(map[string]int),
	}
	if enabled {
		am.rotate()
		go am.rotateLoop()
	}
	return am
}

func randomHex(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (am *authManager) rotate() {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.viewerPw = randomHex(4)
	am.adminPw = randomHex(4)
	am.tokens = make(map[string]session)
	am.fakeTokens = make(map[string]session)
	am.failures = make(map[string]int)
	log.Printf("[AUTH] viewer password: %s (valid for %s)", am.viewerPw, am.interval)
	log.Printf("[AUTH] admin  password: %s (valid for %s)", am.adminPw, am.interval)
}

func (am *authManager) rotateLoop() {
	ticker := time.NewTicker(am.interval)
	defer ticker.Stop()
	for range ticker.C {
		am.rotate()
	}
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (am *authManager) fakeLogin(ip string) (string, string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	token := "fake_" + randomHex(16)
	am.fakeTokens[token] = session{Role: roleFake, IssuedAt: time.Now()}
	return token, roleViewer
}

func (am *authManager) noteLoginFailure(ip string) int {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.failures[ip]++
	return am.failures[ip]
}

func (am *authManager) clearLoginFailures(ip string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.failures, ip)
}

func (am *authManager) isFakeToken(token string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	_, ok := am.fakeTokens[token]
	return ok
}

func (am *authManager) login(password string) (string, string, bool) {
	if !am.enabled {
		return "", roleAdmin, true
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	role := ""
	switch password {
	case am.viewerPw:
		role = roleViewer
	case am.adminPw:
		role = roleAdmin
	default:
		return "", "", false
	}

	token := randomHex(16)
	am.tokens[token] = session{Role: role, IssuedAt: time.Now()}
	return token, role, true
}

func (am *authManager) sessionForToken(token string) (session, bool) {
	if !am.enabled {
		return session{Role: roleAdmin, IssuedAt: time.Now()}, true
	}
	am.mu.RLock()
	defer am.mu.RUnlock()
	s, ok := am.tokens[token]
	return s, ok
}

func roleFromRequest(r *http.Request) string {
	v := r.Context().Value(roleContextKey)
	role, ok := v.(string)
	if !ok || role == "" {
		return roleAdmin
	}
	return role
}

func tokenFromRequest(r *http.Request) string {
	token := r.URL.Query().Get("token")
	if token != "" {
		return token
	}
	return r.Header.Get("X-Auth-Token")
}

func (am *authManager) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !am.enabled {
			ctx := context.WithValue(r.Context(), roleContextKey, roleAdmin)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		switch r.URL.Path {
		case "/", "/index.html", "/api/login", "/api/auth-status":
			next.ServeHTTP(w, r)
			return
		}

		token := tokenFromRequest(r)
		if am.isFakeToken(token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s, ok := am.sessionForToken(token)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), roleContextKey, s.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type Container struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	Status    string `json:"status"`
	State     string `json:"state"`
	Created   string `json:"created"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

func parseSensitivity(labels string) bool {
	if labels == "" {
		return false
	}
	for _, pair := range strings.Split(labels, ",") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == labelKey && strings.EqualFold(kv[1], labelTrue) {
			return true
		}
	}
	return false
}

func listContainers(role string) ([]Container, error) {
	cmd := exec.Command(
		"docker", "ps", "-a",
		"--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.RunningFor}}\t{{.Labels}}",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	var containers []Container
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 7 {
			continue
		}

		sensitive := parseSensitivity(parts[6])
		if sensitive && role != roleAdmin {
			continue
		}

		containers = append(containers, Container{
			ID:        parts[0],
			Name:      parts[1],
			Image:     parts[2],
			Status:    parts[3],
			State:     parts[4],
			Created:   parts[5],
			Sensitive: sensitive,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan docker ps output failed: %w", err)
	}

	return containers, nil
}

func hasAccessToContainer(role, containerID string) (bool, error) {
	containers, err := listContainers(roleAdmin)
	if err != nil {
		return false, err
	}
	for _, c := range containers {
		if c.ID == containerID || c.Name == containerID {
			if c.Sensitive && role != roleAdmin {
				return false, nil
			}
			return true, nil
		}
	}
	return false, nil
}

func handleContainers(w http.ResponseWriter, r *http.Request) {
	containers, err := listContainers(roleFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(containers)
}

func handleContainerAction(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.ID == "" || req.Action == "" {
		http.Error(w, "missing id or action", http.StatusBadRequest)
		return
	}
	args := []string{}
	switch req.Action {
	case "start", "stop", "restart":
		args = []string{req.Action, req.ID}
	case "remove":
		args = []string{"rm", req.ID}
	default:
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	action := "container." + req.Action
	if err != nil {
		recordAudit(r, action, req.ID, false, string(out))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	recordAudit(r, action, req.ID, true, string(out))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}

func handleContainerInspect(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	containerID := r.URL.Query().Get("id")
	if containerID == "" {
		http.Error(w, "missing container id", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", "inspect", containerID).CombinedOutput()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	var data any
	if err := json.Unmarshal(out, &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	containerID := r.URL.Query().Get("id")
	if containerID == "" {
		http.Error(w, "missing container id", http.StatusBadRequest)
		return
	}

	allowed, err := hasAccessToContainer(roleFromRequest(r), containerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	var writeMu sync.Mutex
	writeMsg := func(b []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(websocket.TextMessage, b)
	}

	cmd := exec.CommandContext(ctx, "docker", "logs", "-f", "--tail", defaultTailLine, "--timestamps", containerID)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = writeMsg([]byte("[ERROR] " + err.Error()))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = writeMsg([]byte("[ERROR] " + err.Error()))
		return
	}
	if err := cmd.Start(); err != nil {
		_ = writeMsg([]byte("[ERROR] " + err.Error()))
		return
	}

	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()

	streamPipe := func(pipe interface{ Read([]byte) (int, error) }) {
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line := append([]byte(nil), scanner.Bytes()...)
			if err := writeMsg(line); err != nil {
				cancel()
				return
			}
		}
		if err := scanner.Err(); err != nil {
			_ = writeMsg([]byte("[ERROR] " + err.Error()))
			cancel()
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); streamPipe(stdout) }()
	go func() { defer wg.Done(); streamPipe(stderr) }()
	wg.Wait()
	_ = cmd.Wait()
}

func handleLogsHistory(w http.ResponseWriter, r *http.Request) {
	containerID := r.URL.Query().Get("id")
	if containerID == "" {
		http.Error(w, "missing container id", http.StatusBadRequest)
		return
	}

	allowed, err := hasAccessToContainer(roleFromRequest(r), containerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "500"
	}
	var n int
	if _, err := fmt.Sscanf(tail, "%d", &n); err != nil || n < 1 {
		n = 500
	}
	if n > 5000 {
		n = 5000
	}

	cmd := exec.Command("docker", "logs", "--tail", fmt.Sprintf("%d", n), "--timestamps", containerID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lines)
}

// --- Compose projects ---

type ComposeProject struct {
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	ConfigDir string   `json:"config_dir"`
	Services  []string `json:"services"`
}

func listComposeProjects() ([]ComposeProject, error) {
	out, err := exec.Command("docker", "compose", "ls", "--all", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("docker compose ls failed: %w", err)
	}
	var raw []struct {
		Name      string `json:"Name"`
		Status    string `json:"Status"`
		ConfigDir string `json:"ConfigFiles"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	var projects []ComposeProject
	for _, r := range raw {
		services := []string{}
		if r.ConfigDir != "" {
			if psOut, err := exec.Command("docker", "compose", "-f", r.ConfigDir, "ps", "--format", "{{.Service}}").Output(); err == nil {
				for _, s := range strings.Fields(string(psOut)) {
					services = append(services, s)
				}
			}
		}
		projects = append(projects, ComposeProject{
			Name: r.Name, Status: r.Status, ConfigDir: r.ConfigDir, Services: services,
		})
	}
	return projects, nil
}

func handleComposeProjects(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	projects, err := listComposeProjects()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(projects)
}

func handleComposeAction(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Dir    string `json:"dir"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Dir == "" || req.Action == "" {
		http.Error(w, "missing dir or action", http.StatusBadRequest)
		return
	}
	var args []string
	switch req.Action {
	case "up":
		args = []string{"-f", req.Dir, "up", "-d"}
	case "down":
		args = []string{"-f", req.Dir, "down"}
	case "restart":
		args = []string{"-f", req.Dir, "restart"}
	default:
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", append([]string{"compose"}, args...)...).CombinedOutput()
	action := "compose." + req.Action
	if err != nil {
		recordAudit(r, action, req.Dir, false, string(out))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	recordAudit(r, action, req.Dir, true, string(out))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}

func handleComposeFile(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		http.Error(w, "missing dir", http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"content": string(data)})
}

// --- Volumes ---

type Volume struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint"`
}

func handleVolumes(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	out, err := exec.Command("docker", "volume", "ls", "--format", "{{.Name}}\t{{.Driver}}\t{{.Mountpoint}}").Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var volumes []Volume
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 3 {
			continue
		}
		volumes = append(volumes, Volume{Name: parts[0], Driver: parts[1], Mountpoint: parts[2]})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(volumes)
}

func handleVolumeDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	name := r.URL.Query().Get("id")
	if name == "" {
		http.Error(w, "missing volume name", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", "volume", "rm", name).CombinedOutput()
	if err != nil {
		recordAudit(r, "volume.delete", name, false, string(out))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	recordAudit(r, "volume.delete", name, true, string(out))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}

func handleVolumePrune(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	out, err := exec.Command("docker", "volume", "prune", "-f").CombinedOutput()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	recordAudit(r, "volume.prune", "all", true, string(out))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}

// --- Networks ---

type Network struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Driver  string `json:"driver"`
	Scope   string `json:"scope"`
}

func handleNetworks(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	out, err := exec.Command("docker", "network", "ls", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}").Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var networks []Network
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 4 {
			continue
		}
		networks = append(networks, Network{ID: parts[0], Name: parts[1], Driver: parts[2], Scope: parts[3]})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(networks)
}

func handleNetworkInspect(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing network id", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", "network", "inspect", id).CombinedOutput()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	var data any
	if err := json.Unmarshal(out, &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func handleNetworkDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing network id", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", "network", "rm", id).CombinedOutput()
	if err != nil {
		recordAudit(r, "network.delete", id, false, string(out))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	recordAudit(r, "network.delete", id, true, string(out))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			containers, err := listContainers(roleFromRequest(r))
			if err != nil {
				continue
			}
			data, _ := json.Marshal(containers)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

type AuditEntry struct {
	Time    string `json:"time"`
	Role    string `json:"role"`
	Remote  string `json:"remote"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
}

var (
	auditMu      sync.Mutex
	auditEntries []AuditEntry
)

func gazeConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, ".gaze-docker")
}

func gazeSubDir(name string) string {
	dir := filepath.Join(gazeConfigDir(), name)
	os.MkdirAll(dir, 0755)
	return dir
}

func recordAudit(r *http.Request, action, target string, success bool, output string) {
	output = strings.TrimSpace(output)
	if len(output) > 4000 {
		output = output[:4000] + "..."
	}
	entry := AuditEntry{
		Time:    time.Now().Format(time.RFC3339),
		Role:    roleFromRequest(r),
		Remote:  r.RemoteAddr,
		Action:  action,
		Target:  target,
		Success: success,
		Output:  output,
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditEntries = append([]AuditEntry{entry}, auditEntries...)
	if len(auditEntries) > 200 {
		auditEntries = auditEntries[:200]
	}
	// persist to disk (best-effort)
	if data, err := json.Marshal(entry); err == nil {
		f, err := os.OpenFile(filepath.Join(gazeConfigDir(), "audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.Write(append(data, '\n'))
			f.Close()
		}
	}
}

func handleTemplates(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	dir := gazeSubDir("compose-templates")
	if r.Method == http.MethodPost {
		var req struct {
			Name string `json:"name"`
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(filepath.Join(dir, req.Name+".yml"), []byte(req.Body), 0644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	entries, _ := os.ReadDir(dir)
	type tmpl struct {
		Name string `json:"name"`
		Body string `json:"body"`
	}
	var templates []tmpl
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		templates = append(templates, tmpl{Name: strings.TrimSuffix(e.Name(), ".yml"), Body: string(body)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(templates)
}

func handleTemplateDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	name := r.URL.Query().Get("id")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	dir := gazeSubDir("compose-templates")
	if err := os.Remove(filepath.Join(dir, name+".yml")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleDeployHistory(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	dir := gazeSubDir("deploy-history")
	entries, _ := os.ReadDir(dir)
	type hist struct {
		Name string `json:"name"`
		Body string `json:"body"`
	}
	var history []hist
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.IsDir() {
			continue
		}
		body, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		history = append(history, hist{Name: e.Name(), Body: string(body)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(history)
}

var alertWebhook = os.Getenv("ALERT_WEBHOOK")

func handleAlert(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Container string `json:"container"`
		Message   string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	log.Printf("[ALERT] container=%s message=%s", req.Container, req.Message)
	if alertWebhook != "" {
		payload, _ := json.Marshal(map[string]string{
			"container": req.Container,
			"message":   req.Message,
			"time":      time.Now().Format(time.RFC3339),
		})
		go func() {
			resp, err := http.Post(alertWebhook, "application/json", strings.NewReader(string(payload)))
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	auditMu.Lock()
	entries := append([]AuditEntry(nil), auditEntries...)
	auditMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

type Image struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Size       string `json:"size"`
	Created    string `json:"created"`
}

func requireAdmin(r *http.Request) bool {
	return roleFromRequest(r) == roleAdmin
}

func listImages() ([]Image, error) {
	cmd := exec.Command("docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker images failed: %w", err)
	}
	var images []Image
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 5 {
			continue
		}
		images = append(images, Image{
			ID:         parts[0],
			Repository: parts[1],
			Tag:        parts[2],
			Size:       parts[3],
			Created:    parts[4],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan docker images output failed: %w", err)
	}
	return images, nil
}

func handleImageList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	images, err := listImages()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(images)
}

func handleImageDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	imageID := r.URL.Query().Get("id")
	if imageID == "" {
		http.Error(w, "missing image id", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", "rmi", imageID).CombinedOutput()
	if err != nil {
		recordAudit(r, "image.delete", imageID, false, string(out))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	recordAudit(r, "image.delete", imageID, true, string(out))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}

func handleImageLoad(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseMultipartForm(512 << 20) // 512MB max
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmpDir := filepath.Join(os.TempDir(), "gaze-load")
	os.MkdirAll(tmpDir, 0755)
	tmpPath := filepath.Join(tmpDir, header.Filename)
	dst, err := os.Create(tmpPath)
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}
	dst.Close()
	defer os.Remove(tmpPath)

	out, err := exec.Command("docker", "load", "-i", tmpPath).CombinedOutput()
	if err != nil {
		recordAudit(r, "image.load", header.Filename, false, string(out))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	recordAudit(r, "image.load", header.Filename, true, string(out))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Image   string `json:"image"`
		Compose string `json:"compose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Compose != "" {
		tmpDir := filepath.Join(os.TempDir(), "gaze-deploy", fmt.Sprintf("%d", time.Now().UnixNano()))
		os.MkdirAll(tmpDir, 0755)
		defer os.RemoveAll(tmpDir)
		composePath := filepath.Join(tmpDir, "docker-compose.yml")
		if err := os.WriteFile(composePath, []byte(req.Compose), 0644); err != nil {
			http.Error(w, "failed to write compose file", http.StatusInternalServerError)
			return
		}
		out, err := exec.Command("docker", "compose", "-f", composePath, "up", "-d").CombinedOutput()
		if err != nil {
			recordAudit(r, "deploy.compose", "docker-compose.yml", false, string(out))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
			return
		}
		recordAudit(r, "deploy.compose", "docker-compose.yml", true, string(out))
		histDir := gazeSubDir("deploy-history")
		os.WriteFile(filepath.Join(histDir, fmt.Sprintf("compose-%d.yml", time.Now().UnixNano())), []byte(req.Compose), 0644)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
		return
	}

	if req.Image == "" {
		http.Error(w, "missing image or compose", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", "run", "-d", req.Image).CombinedOutput()
	if err != nil {
		recordAudit(r, "deploy.image", req.Image, false, string(out))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	recordAudit(r, "deploy.image", req.Image, true, string(out))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "output": strings.TrimSpace(string(out))})
}

type FileEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"isDir"`
}

type ServerStats struct {
	CPUUsage          string `json:"cpu_usage"`
	MemoryUsed        string `json:"memory_used"`
	MemoryTotal       string `json:"memory_total"`
	MemoryPct         string `json:"memory_pct"`
	DiskUsed          string `json:"disk_used"`
	DiskTotal         string `json:"disk_total"`
	DiskPct           string `json:"disk_pct"`
	ContainersRunning int    `json:"containers_running"`
	ContainersTotal   int    `json:"containers_total"`
	ImagesCount       int    `json:"images_count"`
}

func cleanTarPath(p string) string {
	p = strings.TrimPrefix(filepath.ToSlash(p), "./")
	p = strings.TrimPrefix(p, "/")
	return p
}

func directChild(base, p string) (string, bool) {
	base = strings.Trim(strings.TrimPrefix(filepath.ToSlash(base), "/"), "/")
	p = cleanTarPath(p)
	if base != "" {
		if p == base {
			return "", false
		}
		prefix := base + "/"
		if !strings.HasPrefix(p, prefix) {
			return "", false
		}
		p = strings.TrimPrefix(p, prefix)
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return "", false
	}
	parts := strings.SplitN(p, "/", 2)
	return parts[0], true
}

func handleImageFiles(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	imageID := r.URL.Query().Get("id")
	if imageID == "" {
		http.Error(w, "missing image id", http.StatusBadRequest)
		return
	}
	basePath := r.URL.Query().Get("path")
	containerName := "gaze-browse-" + randomHex(6)
	if out, err := exec.Command("docker", "create", "--name", containerName, imageID).CombinedOutput(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	defer exec.Command("docker", "rm", containerName).Run()

	cmd := exec.Command("docker", "export", containerName)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cmd.Start(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	entries := map[string]FileEntry{}
	tr := tar.NewReader(stdout)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = cmd.Wait()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		name, ok := directChild(basePath, hdr.Name)
		if !ok {
			continue
		}
		fullPath := "/" + strings.Trim(strings.Trim(basePath, "/")+"/"+name, "/")
		entry := entries[name]
		entry.Name = name
		entry.Path = fullPath
		if hdr.FileInfo().IsDir() || strings.Contains(strings.TrimPrefix(cleanTarPath(hdr.Name), strings.Trim(basePath, "/")+"/"+name), "/") {
			entry.IsDir = true
		}
		if !entry.IsDir {
			entry.Size = hdr.Size
		}
		entries[name] = entry
	}
	if err := cmd.Wait(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	files := make([]FileEntry, 0, len(entries))
	for _, entry := range entries {
		files = append(files, entry)
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"path": basePath, "files": files})
}

func parsePercent(v string) float64 {
	v = strings.TrimSpace(strings.TrimSuffix(v, "%"))
	f, _ := strconv.ParseFloat(v, 64)
	return f
}

type ContainerStat struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	CPU    float64 `json:"cpu"`
	MemUse string  `json:"mem_use"`
	MemPct float64 `json:"mem_pct"`
	NetIO  string  `json:"net_io"`
	Block  string  `json:"block_io"`
	PIDs   string  `json:"pids"`
}

func handleContainerStats(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.ID}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}").Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var stats []ContainerStat
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 8 {
			continue
		}
		memUse := ""
		memParts := strings.Split(parts[3], " / ")
		if len(memParts) > 0 {
			memUse = memParts[0]
		}
		stats = append(stats, ContainerStat{
			ID: parts[0], Name: parts[1], CPU: parsePercent(parts[2]),
			MemUse: memUse, MemPct: parsePercent(parts[4]),
			NetIO: parts[5], Block: parts[6], PIDs: parts[7],
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func handleImageInspect(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing image id", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", "image", "inspect", id).CombinedOutput()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(out)})
		return
	}
	var data any
	if err := json.Unmarshal(out, &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func handleExec(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	containerID := r.URL.Query().Get("id")
	if containerID == "" {
		http.Error(w, "missing container id", http.StatusBadRequest)
		return
	}
	allowed, err := hasAccessToContainer(roleFromRequest(r), containerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("exec websocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", containerID, "sh")
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "docker", "exec", "-i", containerID, "cmd")
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("[ERROR] "+err.Error()))
		return
	}

	// stdout -> websocket
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				if werr := conn.WriteMessage(websocket.TextMessage, buf[:n]); werr != nil {
					cancel()
					return
				}
			}
			if rerr != nil {
				cancel()
				return
			}
		}
	}()

	// websocket -> stdin
	for {
		_, data, rerr := conn.ReadMessage()
		if rerr != nil {
			cancel()
			break
		}
		if _, werr := stdin.Write(append(data, '\n')); werr != nil {
			cancel()
			break
		}
	}
	_ = cmd.Wait()
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	stats := ServerStats{CPUUsage: "0%", MemoryUsed: "-", MemoryTotal: "-", MemoryPct: "-", DiskUsed: "-", DiskTotal: "-", DiskPct: "-"}
	if containers, err := listContainers(roleAdmin); err == nil {
		stats.ContainersTotal = len(containers)
		for _, c := range containers {
			if c.State == "running" {
				stats.ContainersRunning++
			}
		}
	}
	if images, err := listImages(); err == nil {
		stats.ImagesCount = len(images)
	}
	if out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}").Output(); err == nil {
		var cpu float64
		var memUsed, memTotal, memPct string
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), "\t")
			if len(parts) < 3 {
				continue
			}
			cpu += parsePercent(parts[0])
			memPct = parts[2]
			usage := strings.Split(parts[1], " / ")
			if len(usage) == 2 {
				memUsed = usage[0]
				memTotal = usage[1]
			}
		}
		stats.CPUUsage = fmt.Sprintf("%.1f%%", cpu)
		if memUsed != "" {
			stats.MemoryUsed = memUsed
			stats.MemoryTotal = memTotal
			stats.MemoryPct = memPct
		}
	}
	if runtime.GOOS != "windows" {
		if out, err := exec.Command("df", "-h", "/").Output(); err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(lines) >= 2 {
				parts := strings.Fields(lines[1])
				if len(parts) >= 5 {
					stats.DiskTotal = parts[1]
					stats.DiskUsed = parts[2]
					stats.DiskPct = parts[4]
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func handleLogin(am *authManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		ip := clientIP(r)
		token, role, ok := am.login(req.Password)
		if !ok {
			failures := am.noteLoginFailure(ip)
			if failures >= fakeFailLimit {
				fakeToken, fakeRole := am.fakeLogin(ip)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"token": fakeToken,
					"role":  fakeRole,
					"fake":  "true",
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "wrong password"})
			return
		}
		am.clearLoginFailures(ip)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": token,
			"role":  role,
		})
	}
}

func handleAuthStatus(am *authManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth_required": am.enabled,
			"roles":         []string{roleViewer, roleAdmin},
		})
	}
}

func main() {
	port := flag.String("port", "", "port to listen on (default: 8080, env: PORT)")
	auth := flag.String("auth", "", "enable auth: true/false (default: false, env: AUTH)")
	authRotate := flag.String("auth-rotate", "", "password rotation interval (default: 1h, env: AUTH_ROTATE)")
	flag.Parse()

	listenPort := defaultPort
	if v := os.Getenv("PORT"); v != "" {
		listenPort = v
	}
	if *port != "" {
		listenPort = *port
	}

	authEnabled := false
	authValue := os.Getenv("AUTH")
	if *auth != "" {
		authValue = *auth
	}
	if authValue == "true" || authValue == "1" {
		authEnabled = true
	}

	rotateInterval := defaultRotate
	rotateValue := os.Getenv("AUTH_ROTATE")
	if *authRotate != "" {
		rotateValue = *authRotate
	}
	if rotateValue != "" {
		d, err := time.ParseDuration(rotateValue)
		if err != nil || d <= 0 {
			log.Printf("[WARN] invalid AUTH_ROTATE value %q, using default %s", rotateValue, defaultRotate)
		} else {
			rotateInterval = d
		}
	}

	am := newAuthManager(authEnabled, rotateInterval)

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/api/auth-status", handleAuthStatus(am))
	mux.HandleFunc("/api/login", handleLogin(am))
	mux.HandleFunc("/api/containers", handleContainers)
	mux.HandleFunc("/api/containers/action", handleContainerAction)
	mux.HandleFunc("/api/containers/inspect", handleContainerInspect)
	mux.HandleFunc("/api/logs", handleLogs)
	mux.HandleFunc("/api/logs/history", handleLogsHistory)
	mux.HandleFunc("/api/refresh", handleRefresh)
	mux.HandleFunc("/api/images", handleImageList)
	mux.HandleFunc("/api/images/delete", handleImageDelete)
	mux.HandleFunc("/api/images/load", handleImageLoad)
	mux.HandleFunc("/api/images/files", handleImageFiles)
	mux.HandleFunc("/api/deploy", handleDeploy)
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/api/audit", handleAudit)
	mux.HandleFunc("/api/compose/projects", handleComposeProjects)
	mux.HandleFunc("/api/compose/action", handleComposeAction)
	mux.HandleFunc("/api/compose/file", handleComposeFile)
	mux.HandleFunc("/api/volumes", handleVolumes)
	mux.HandleFunc("/api/volumes/delete", handleVolumeDelete)
	mux.HandleFunc("/api/volumes/prune", handleVolumePrune)
	mux.HandleFunc("/api/networks", handleNetworks)
	mux.HandleFunc("/api/networks/inspect", handleNetworkInspect)
	mux.HandleFunc("/api/networks/delete", handleNetworkDelete)
	mux.HandleFunc("/api/containers/stats", handleContainerStats)
	mux.HandleFunc("/api/images/inspect", handleImageInspect)
	mux.HandleFunc("/api/exec", handleExec)
	mux.HandleFunc("/api/templates", handleTemplates)
	mux.HandleFunc("/api/templates/delete", handleTemplateDelete)
	mux.HandleFunc("/api/deploy/history", handleDeployHistory)
	mux.HandleFunc("/api/alert", handleAlert)

	addr := ":" + listenPort
	log.Printf("[BUILD] version=%s commit=%s built_at=%s go=%s platform=%s/%s", buildVersion, buildCommit, buildTime, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if authEnabled {
		log.Printf("Gaze Docker running at http://localhost%s (auth ON)", addr)
	} else {
		log.Printf("Gaze Docker running at http://localhost%s (auth OFF)", addr)
	}
	if err := http.ListenAndServe(addr, am.middleware(mux)); err != nil {
		log.Fatal(err)
	}
}
