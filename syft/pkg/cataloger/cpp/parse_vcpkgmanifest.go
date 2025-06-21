package cpp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp/internal/vcpkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseVcpkgmanifest

var defaultRegistry = pkg.VcpkgRegistry{
	Kind:       pkg.Git,
	Repository: "https://github.com/microsoft/vcpkg",
}

func parseVcpkgmanifest(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	head := findLockFileHead()
	r := vcpkg.NewResolver(
		pkg.VcpkgConfig{
			DefaultRegistry: defaultRegistry,
		},
	)

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

func findLockFileHead() string {
	return "0cb95c860ea83aafc1b24350510b30dec535989a"
}
