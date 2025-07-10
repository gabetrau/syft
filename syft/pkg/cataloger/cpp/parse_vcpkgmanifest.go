package cpp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp/internal/vcpkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseVcpkgmanifest


func parseVcpkgmanifest(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	lockRecords := findLockFileHead(resolver)
	r := vcpkg.NewResolver(
		pkg.VcpkgConfig{
			DefaultRegistry: pkg.VcpkgRegistry{
				Kind: pkg.Git,
				Repository: lockRecords[0].Repo,
			},
		},
	)
	head := lockRecords[0].Head

	// find full manifests for all dependencies
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	for {
		var pMan pkg.VcpkgManifest
		dec := json.NewDecoder(reader)

		if err := dec.Decode(&pMan); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse vcpkg.json file: %w", err)
		}
		oPkg := newVcpkgPackage(ctx, pMan, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)) 
		pkgs = append(
			pkgs,
			oPkg)

		
		for _, dep := range pMan.Dependencies {
			cMans, fetchErr := r.FindManifestsInRemoteRepository(ctx, dep, head, true, &pMan)
			if fetchErr != nil {
				return nil, nil, fmt.Errorf("failed to fetch vcpkg.json file: %w", fetchErr)
			}
			for _, c := range cMans {
				if c.Child != nil {
					cPkg := newVcpkgPackage(ctx, *c.Child, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
					if c.Parent != nil {
						pPkg := newVcpkgPackage(ctx, *c.Parent, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
						rship := artifact.Relationship{
							From: pPkg,
							To: cPkg,
							Type: artifact.DependencyOfRelationship,
						}
						relationships = append(
							relationships,
							rship)
					}
					pkgs = append(
						pkgs,
						cPkg)
				}
			}
		}
	}

	pkg.Sort(pkgs)
	return pkgs, relationships, nil
}

func findLockFileHead(resolver file.Resolver) []pkg.VcpkgLock {
	loc, err := resolver.FilesByGlob("**/vcpkg-lock.json")
	if err != nil || len(loc) == 0 {
		// may want to throw an error here if a vcpkg-lock.json file is not present
		return []pkg.VcpkgLock{
			pkg.VcpkgLock{
				Repo: "https://github.com/microsoft/vcpkg",
				Head: "master",
			},
		}
	}
	lockContents, err := resolver.FileContentsByLocation(loc[0])
	if err != nil || lockContents == nil {
		return []pkg.VcpkgLock{
			pkg.VcpkgLock{
				Repo: "https://github.com/microsoft/vcpkg", 
				Head: "master",
			},
		}
	}
	defer internal.CloseAndLogError(lockContents, loc[0].RealPath)
	lockBytes, err := io.ReadAll(lockContents)

	var lockFile interface{} 
	json.Unmarshal(lockBytes, &lockFile)

	var lockRecords []pkg.VcpkgLock
	for k, v := range lockFile.(map[string]interface{}) {
		switch t := v.(type) {
		case map[string]interface{}:
			for _, v2 := range t {
				switch t2 := v2.(type) {
				case string:
					lockRecords = append(lockRecords, pkg.VcpkgLock{
						Repo: k,
						Head: t2,
					})
				}
			}
		}
	}
	return lockRecords 
}
