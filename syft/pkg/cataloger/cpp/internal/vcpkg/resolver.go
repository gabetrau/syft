package vcpkg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/syft/pkg"
)

type ManifestNode struct {
	Parent *pkg.VcpkgManifest
	Child *pkg.VcpkgManifest 
}

type ID struct {
	name    string
	version string
}

// Resolver is a short-lived utility to resolve maven poms from multiple sources, including:
// the scanned filesystem, local maven cache directories, remote maven repositories, and the syft cache
type Resolver struct {
	cfg                  pkg.VcpkgConfig
	cache                cache.Cache
	resolved             map[ID]*pkg.VcpkgManifest
	remoteRequestTimeout time.Duration
}

// NewResolver constructs a new Resolver with the given vcpkg configuration.
func NewResolver(cfg pkg.VcpkgConfig) *Resolver {
	return &Resolver{
		cfg:                  cfg,
		cache:                cache.GetManager().GetCache("cpp/vcpkg/repo", "v1"),
		resolved:             map[ID]*pkg.VcpkgManifest{},
		remoteRequestTimeout: time.Second * 10,
	}
}

// cacheResolveReader attempts to get a reader from cache, otherwise caches the contents of the resolve() function.
// this function is guaranteed to return an unread reader for the correct contents.
// NOTE: this could be promoted to the internal cache package as a specialized version of the cache.Resolver
// if there are more users of this functionality
func (r *Resolver) cacheResolveReader(key string, resolve func() (io.ReadCloser, error)) (io.Reader, error) {
	reader, err := r.cache.Read(key)
	if err == nil && reader != nil {
		return reader, err
	}

	contentReader, err := resolve()
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contentReader, key)

	// store the contents to return a new reader with the same content
	contents, err := io.ReadAll(contentReader)
	if err != nil {
		return nil, err
	}
	err = r.cache.Write(key, bytes.NewBuffer(contents))
	return bytes.NewBuffer(contents), err
}

// Get all of the manifest/vcpkg.json files from github 
func (r *Resolver) FindManifestsInRemoteRepository(ctx context.Context, dependency interface{}, head string, df bool, parent *pkg.VcpkgManifest) ([]ManifestNode, error) {
	var name string
	var version string
	defaultFeatures := df
	var features []interface{}
	switch d := dependency.(type) {
	case string:
		name = d
	// assume it's json map of VcpkgDependency
	case map[string]interface{}:
		if d["name"] != nil {
			name = d["name"].(string) 
		}
		if d["version>="] != nil {
			version = d["version>="].(string)
		}
		if d["default-features"] != nil {
			defaultFeatures = defaultFeatures && d["default-features"].(bool)
		}
		if d["features"] != nil {
			features = d["features"].([]interface{})
		}
	}
	if name == "" || head == "" {
		return nil, fmt.Errorf("missing/incomplete vcpkg coordinates -- name: '%s', head: '%s'", name, version, head)
	}
	manNodes := []ManifestNode{}

	if r.cfg.DefaultRegistry.Repository != "" {
		client := http.Client{
			Timeout: r.remoteRequestTimeout,
		}
		vcpkg, err := findPortManifest(client, r.cfg.DefaultRegistry.Repository, name, version, head, defaultFeatures, features, parent)
		if err != nil {
			return nil, fmt.Errorf("vcpkg.json not found")
		}
		manNode := ManifestNode{
			Parent: parent,
			Child: &vcpkg,
		}
		manNodes = append(manNodes, manNode)
		if len(vcpkg.Dependencies) != 0 {
			for _, dep := range vcpkg.Dependencies {
				childManNodes, err := r.FindManifestsInRemoteRepository(ctx, dep, head, df, &vcpkg)
				manNodes = append(manNodes, childManNodes...)
				if err != nil {
					return nil, fmt.Errorf("vcpkg.json not found")
				}
			}
		}
		return manNodes, nil
	}

	return nil, fmt.Errorf("vcpkg.json not found")
}



// returns the raw github vcpkg.json file content from the
func findPortManifest(client http.Client, repo, name, version, head string, df bool, features []interface{}, parent *pkg.VcpkgManifest) (pkg.VcpkgManifest, error) {
	vParts := strings.Split(version, "#")
	var resultVcpkg pkg.VcpkgManifest

	rawRepo := strings.Replace(repo, "github.com", "raw.githubusercontent.com", 1)
	if name == "" {
		return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
	}
	if head == "" {
		return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
	}
	if version != "" {
		requestURL := rawRepo + "/" + head + "/versions/" + name[0:1] + "-/" + name + ".json"
		req, err := http.NewRequest(http.MethodGet, requestURL, nil)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		resp, err := client.Do(req)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		if resp.StatusCode == http.StatusNotFound {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		body, err := io.ReadAll(resp.Body)
		var versions []pkg.VcpkgPortVersion
		verErr := json.Unmarshal(body, &versions)
		if verErr != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		var gitTree string
		for _, v := range versions {
			if len(vParts) > 1 {
				portV, err := strconv.Atoi(vParts[1])
				if err != nil {
					continue
				}
				if v.Version == vParts[0] && v.PortVersion == portV {
					gitTree = v.GitTree
					break
				}
			} else {
				if v.Version == vParts[0] {
					gitTree = v.GitTree
					break
				}
			}
		}
		if gitTree == "" {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}

		// github api tree object request
		apiRepo := strings.Replace(repo, "github.com", "api.github.com/repos", 1)
		apiTreeReqURL := apiRepo + "/git/trees/" + gitTree
		apiTreeReq, err := http.NewRequest(http.MethodGet, apiTreeReqURL, nil)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		apiTreeResp, err := client.Do(apiTreeReq)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		if apiTreeResp.StatusCode == http.StatusNotFound {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		apiTreeBody, err := io.ReadAll(apiTreeResp.Body)
		var treeObj pkg.VcpkgTreeObject
		apiTreeErr := json.Unmarshal(apiTreeBody, &treeObj)
		if apiTreeErr != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		var blobObjUrl string
		for _, t := range treeObj.Tree {
			if t.Path == "vcpkg.json" {
				blobObjUrl = t.Url
			}
		}
		if blobObjUrl == "" {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}

		// github api blob object request
		apiBlobReq, err := http.NewRequest(http.MethodGet, blobObjUrl, nil)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		apiBlobResp, err := client.Do(apiBlobReq)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		if apiBlobResp.StatusCode == http.StatusNotFound {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		apiBlobBody, err := io.ReadAll(apiBlobResp.Body)
		var blobObj pkg.VcpkgBlobObject
		apiBlobErr := json.Unmarshal(apiBlobBody, &blobObj)
		if apiBlobErr != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		encodedCont := strings.ReplaceAll(blobObj.Content, "\n", "")
		decodedCont, err := base64.StdEncoding.DecodeString(encodedCont)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		var blobVcpkg pkg.VcpkgManifest
		json.Unmarshal([]byte(decodedCont), &blobVcpkg)

		resultVcpkg = blobVcpkg
	} else {
		requestURL := rawRepo + "/" + head + "/ports/" + name + "/vcpkg.json"
		req, err := http.NewRequest(http.MethodGet, requestURL, nil)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		resp, err := client.Do(req)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		if resp.StatusCode == http.StatusNotFound {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}
		respBody, err := io.ReadAll(resp.Body)
		var vcpkgMan pkg.VcpkgManifest
		vmErr := json.Unmarshal(respBody, &vcpkgMan)
		if vmErr != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("vcpkg.json not found")
		}

		resultVcpkg = vcpkgMan
	}

	for _, feature := range features {
		switch fo := feature.(type) {
		case string:
			for name, f := range resultVcpkg.Features {
				if fo == name || (df && isDefaultFeature(name, resultVcpkg.DefaultFeatures)) {
					resultVcpkg.Dependencies = append(resultVcpkg.Dependencies, f.Dependencies...)
				}
			}
		case pkg.VcpkgFeatureObject:
			for name, f := range resultVcpkg.Features {
				if fo.Name == name || (df && isDefaultFeature(name, resultVcpkg.DefaultFeatures)) {
					resultVcpkg.Dependencies = append(resultVcpkg.Dependencies, f.Dependencies...)
				}
			}
		}
	}
	return resultVcpkg, nil
}

func isDefaultFeature(name string, defaultFeatures []interface{}) bool {
	for _, df := range defaultFeatures {
		switch d := df.(type) {
			case string:
				if name == d {
					return true
				}
			case map[string]interface{}:
				if name == d["name"].(string) {
					return true
				}
		}
	}
	return false
}
