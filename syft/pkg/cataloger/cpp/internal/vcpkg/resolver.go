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

// Copy of cache resolver in java cataloger.
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
		vcpkg, err := r.findPortManifest(ctx, name, version, head, defaultFeatures, features, parent)
		if err != nil {
			return nil, fmt.Errorf("vcpkg.json not found. %w", err)
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
					return nil, fmt.Errorf("could not find vcpkg.json file for dependency. %w", err)
				}
			}
		}
		return manNodes, nil
	}

	return nil, fmt.Errorf("Could not find a vcpkg registry to search for manifests")
}

// looks up the vcpkg.json from (a.k.a the manifest file)
func (r *Resolver) findPortManifest(ctx context.Context, name, ver, head string, df bool, features []interface{}, parent *pkg.VcpkgManifest) (pkg.VcpkgManifest, error) {
	var resultVcpkg pkg.VcpkgManifest
	var err error
	rawRepo := strings.Replace(r.cfg.DefaultRegistry.Repository, "github.com", "raw.githubusercontent.com", 1)

	// if version is present, lookup is more complicated 
	// Also requires use of github api, so custom vcpkg git registries from other vendors won't work 
	if ver != "" {
		gitTree, err := r.resolveGitTreeSha(ctx, rawRepo, head, name, ver)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("could not find versions json file. head->%v name->%v version->%v. %w", head, name, ver, err)
		}
		blobObjURL, err := r.resolveGitObjectSha(ctx, gitTree)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("could not find blob URL for port. head->%v name->%v version->%v. %w", head, name, ver, err)
		}
		resultVcpkg, err = r.resolveBlobToManifest(ctx, blobObjURL)
		if err != nil {
			return resultVcpkg, err
		}
	} else {
		requestURL := rawRepo + "/" + head + "/ports/" + name + "/vcpkg.json"
		resultVcpkg, err = r.resolveManifest(ctx, requestURL)
		if err != nil {
			return resultVcpkg, err
		}
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

// simply looks up the raw vcpkg.json file at requestURL
func (r *Resolver) resolveManifest(ctx context.Context, requestURL string) (pkg.VcpkgManifest, error) {
	cacheKey := strings.TrimPrefix(strings.TrimPrefix(requestURL, "http://"), "https://")
	reader, err := r.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
		return getReqToCloser(requestURL, ctx, r.remoteRequestTimeout)
	})
	if err != nil {
		return pkg.VcpkgManifest{}, fmt.Errorf("failed to resolve vcpkg.json %v, %w", requestURL, err)
	}
	manBytes, err := io.ReadAll(reader) 
	if err != nil {
		return pkg.VcpkgManifest{}, fmt.Errorf("could not read bytes for vcpkg.json. %w", err)
	}
	var resultVcpkg pkg.VcpkgManifest
	err = json.Unmarshal(manBytes, &resultVcpkg)
	if err != nil {
		return pkg.VcpkgManifest{}, fmt.Errorf("could not convert vcpkg.json into VcpkgManifest struct. %w", err)
	}

	return resultVcpkg, nil
}

// Look up blob object and decode the contents. See https://docs.github.com/en/rest/git/blobs?apiVersion=2022-11-28
func (r *Resolver) resolveBlobToManifest(ctx context.Context, blobObjURL string) (pkg.VcpkgManifest, error) {
	cacheKey := strings.TrimPrefix(strings.TrimPrefix(blobObjURL, "http://"), "https://")
	reader, err := r.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
		return getReqToCloser(blobObjURL, ctx, r.remoteRequestTimeout)
	})
	if err != nil {
		return pkg.VcpkgManifest{}, fmt.Errorf("failed to resolve vcpkg.json blob %v, %w", blobObjURL, err)
	}
	manBytes, err := io.ReadAll(reader) 
	if err != nil {
		return pkg.VcpkgManifest{}, fmt.Errorf("could not read bytes for vcpkg.json blob. %w", err)
	}
	var blobObj pkg.VcpkgBlobObject
	err = json.Unmarshal(manBytes, &blobObj)
	if err != nil {
		return pkg.VcpkgManifest{}, fmt.Errorf("could not convert vcpkg.json into VcpkgBlobObject struct. %w", err)
	}
	encodedCont := strings.ReplaceAll(blobObj.Content, "\n", "")
	decodedCont, err := base64.StdEncoding.DecodeString(encodedCont)
	if err != nil {
		return pkg.VcpkgManifest{}, fmt.Errorf("failed to decode base64 content to byte array. %w", err)
	}
	var blobVcpkg pkg.VcpkgManifest
	err = json.Unmarshal([]byte(decodedCont), &blobVcpkg)
	if err != nil {
		return pkg.VcpkgManifest{}, fmt.Errorf("failed to unmarshal byte array to VcpkgManifest struct. %w", err)
	}

	return blobVcpkg, nil
}


// find blob object sha via api call to github.  
// https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28 
func (r *Resolver) resolveGitObjectSha(ctx context.Context, gitTree string) (string, error) {
	apiRepo := strings.Replace(r.cfg.DefaultRegistry.Repository, "github.com", "api.github.com/repos", 1)
	apiTreeReqURL := apiRepo + "/git/trees/" + gitTree
	cacheKey := strings.TrimPrefix(strings.TrimPrefix(apiTreeReqURL, "http://"), "https://")
	reader, err := r.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
		return getReqToCloser(apiTreeReqURL, ctx, r.remoteRequestTimeout)
	})
	if err != nil {
		return "", fmt.Errorf("failed to resolve vcpkg.json %v, %w", apiTreeReqURL, err)
	}
	atrBytes, err := io.ReadAll(reader) 
	if err != nil {
		return "", fmt.Errorf("could not read bytes for vcpkg.json. %w", err)
	}
	var treeObj pkg.VcpkgTreeObject
	err = json.Unmarshal(atrBytes, &treeObj)
	if err != nil {
		return "", fmt.Errorf("could not convert vcpkg.json into VcpkgManifest struct. %w", err)
	}
	var blobObjUrl string
	for _, t := range treeObj.Tree {
		if t.Path == "vcpkg.json" {
			blobObjUrl = t.Url
		}
	}
	if blobObjUrl == "" {
		return "", fmt.Errorf("could not find vcpkg.json blob at tree url. %v", apiTreeReqURL)
	}
	return blobObjUrl, nil 
}


// find versions file from registry for port 
func (r *Resolver) resolveGitTreeSha(ctx context.Context, rawRepo, head, name, ver string) (string, error) {
	vParts := strings.Split(ver, "#")
	verReqURL := rawRepo + "/" + head + "/versions/" + name[0:1] + "-/" + name + ".json"
	cacheKey := strings.TrimPrefix(strings.TrimPrefix(verReqURL, "http://"), "https://")
	reader, err := r.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
		return getReqToCloser(verReqURL, ctx, r.remoteRequestTimeout)
	})
	if err != nil {
		return "", fmt.Errorf("failed to resolve vcpkg.json %v, %w", verReqURL, err)
	}
	if reader, ok := reader.(io.Closer); ok {
		defer internal.CloseAndLogError(reader, verReqURL)
	}
	verBytes, err := io.ReadAll(reader) 
	if err != nil {
		return "", fmt.Errorf("could not read bytes for vcpkg.json. %w", err)
	}
	var versions []pkg.VcpkgPortVersion
	err = json.Unmarshal(verBytes, &versions)
	if err != nil {
		return "", fmt.Errorf("could not convert vcpkg.json into VcpkgManifest struct. %w", err)
	}

	// get tree object sha for the port version
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
		return "", fmt.Errorf("could not identify a git tree sha for vcpkg.json from url %v. version %v", verReqURL, ver)
	}
	return gitTree, nil
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

func getReqToCloser(requestURL string, ctx context.Context, to time.Duration) (io.ReadCloser, error) {
	if requestURL == "" {
		return nil, fmt.Errorf("vcpkg request URL cannot be blank")
	}
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request for vcpkg: %w", err)
	}

	req = req.WithContext(ctx)

	client := http.Client{
		Timeout: to,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to get manifest from vcpkg registry %v: %w", requestURL, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("manifest not found in vcpkg registry at: %v", requestURL)
	}
	return resp.Body, err
}
