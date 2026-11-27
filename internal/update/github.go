package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxUpdateSize = 64 << 20

var versionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$`)

type Release struct {
	Version string
	Digest  string
	Size    int64
	assetID int64
}

type GitHub struct {
	repo   string
	base   string
	client *http.Client
}

func NewGitHub(repo string) *GitHub {
	return &GitHub{repo: repo, base: "https://api.github.com",
		client: &http.Client{
			Timeout: 2 * time.Minute,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				host := request.URL.Hostname()
				if len(via) >= 5 || request.URL.Scheme != "https" || request.URL.User != nil ||
					(host != "api.github.com" && host != "github.com" &&
						host != "objects.githubusercontent.com" && host != "release-assets.githubusercontent.com") {
					return errors.New("GitHub 更新下载重定向地址无效")
				}
				return nil
			},
		},
	}
}

func versionParts(s string) ([3]int, bool) {
	var value [3]int
	parts := versionPattern.FindStringSubmatch(s)
	if parts == nil {
		return value, false
	}
	for i := range value {
		var err error
		value[i], err = strconv.Atoi(parts[i+1])
		if err != nil {
			return value, false
		}
	}
	return value, true
}

func newer(latest, current [3]int) bool {
	for i, part := range latest {
		if part != current[i] {
			return part > current[i]
		}
	}
	return false
}

func (g *GitHub) request(ctx context.Context, endpoint, accept string) (*http.Response, error) {
	if !repoPattern.MatchString(g.repo) {
		return nil, errors.New("升级仓库配置无效")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.base+"/repos/"+g.repo+endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "GatewayModuleAnalyzer")
	res, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("访问 GitHub 失败: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests || (res.StatusCode == http.StatusForbidden && res.Header.Get("X-RateLimit-Remaining") == "0") {
			return nil, errors.New("GitHub 更新检查达到请求上限，请稍后重试")
		}
		return nil, fmt.Errorf("GitHub 返回 HTTP %d，请检查网络和公开发行版是否可访问", res.StatusCode)
	}
	return res, nil
}

func (g *GitHub) Latest(ctx context.Context, current, arch string) (*Release, error) {
	currentVersion, ok := versionParts(current)
	if !ok {
		return nil, errors.New("当前构建没有正式版本号")
	}
	response, err := g.request(ctx, "/releases/latest", "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var latest struct {
		Version    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&latest); err != nil {
		return nil, err
	}
	latestVersion, ok := versionParts(latest.Version)
	if !ok || latest.Draft || latest.Prerelease {
		return nil, errors.New("GitHub 最新发行版的版本号无效")
	}
	if !newer(latestVersion, currentVersion) {
		return nil, nil
	}
	name := "GatewayModuleAnalyzer-Windows-" + arch + ".exe"
	for _, asset := range latest.Assets {
		if asset.Name != name || asset.ID <= 0 {
			continue
		}
		if asset.Size <= 0 || asset.Size > maxUpdateSize || !strings.HasPrefix(asset.Digest, "sha256:") {
			break
		}
		digest := strings.TrimPrefix(asset.Digest, "sha256:")
		if validDigest(digest) {
			return &Release{Version: latest.Version, Digest: strings.ToLower(digest), Size: asset.Size, assetID: asset.ID}, nil
		}
	}
	return nil, errors.New("发行版缺少对应 Windows 架构的已校验 EXE")
}

func (g *GitHub) Download(ctx context.Context, release *Release, directory string) (string, error) {
	response, err := g.request(ctx, "/releases/assets/"+strconv.FormatInt(release.assetID, 10), "application/octet-stream")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	file, err := os.CreateTemp(directory, ".gateway-update-*.bin")
	if err != nil {
		return "", err
	}
	path := file.Name()
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, release.Size+1))
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil && (n != release.Size || hex.EncodeToString(digest.Sum(nil)) != release.Digest) {
		err = errors.New("下载文件大小或 SHA-256 校验失败")
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func validDigest(digest string) bool {
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}

func Verify(path, digest string) error {
	if !validDigest(digest) {
		return errors.New("升级校验值无效")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxUpdateSize+1))
	if err != nil {
		return err
	}
	if n > maxUpdateSize || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), digest) {
		return errors.New("升级文件的 SHA-256 校验失败")
	}
	return nil
}
