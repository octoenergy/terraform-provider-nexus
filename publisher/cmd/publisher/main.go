package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	flag "github.com/spf13/pflag"

	"github.com/datadrivers/terraform-provider-nexus/publisher"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	debug := flag.Bool("debug", false, "sets verbose")
	pretty := flag.Bool("pretty", true, "sets pretty output")
	// Defaults here are all public hashicorp values
	repo := flag.String("repo", "none", "GitHub repository path - org/name")
	org := flag.String("tf-org", "none", "Terraform organization")
	provider := flag.String("provider", "none", "Provider name")
	version := flag.String("version", "none", "Provider version without the 'v' prefix, if present")
	keyID := flag.String("gpg-key", "none", "GPG key ID")
	regType := flag.String("reg-type", "private", "Terraform registry type")
	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if *pretty {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	}

	if *repo == "none" || *org == "none" || *provider == "none" || *version == "none" || *keyID == "none" {
		log.Error().Msg("missing required flags")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// get the auth token
	token := publisher.GetToken()

	// set up the client with headers etc
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	providerConfig := publisher.Config{
		RepositoryPath:  *repo,
		TFOrganization:  *org,
		ProviderName:    *provider,
		ProviderVersion: *version,
		GPGKeyId:        *keyID,
		// TODO: matrix this
		Platforms: []publisher.Platform{
			{OS: "linux", Arch: "amd64"},
			{OS: "linux", Arch: "arm64"},
			{OS: "darwin", Arch: "amd64"},
			{OS: "darwin", Arch: "arm64"},
			{OS: "windows", Arch: "amd64"},
			{OS: "windows", Arch: "arm64"},
		},
		TFRegistryType: *regType,
		Token:          token,
	}
	pub := publisher.Publisher{
		Config: providerConfig,
		Client: client,
	}

	// Setup done, now we can start the process
	err := pub.CreateProvider()
	if err != nil {
		log.Error().Err(err).Msg("error creating provider")
		return
	}
	log.Info().Msg("provider created")

	versionLinks, err := pub.CreateVersion()
	if err != nil || versionLinks == nil {
		log.Error().Err(err).Msg("error creating version")
		return
	}
	log.Info().Msgf("version created, versionLinks: %v", versionLinks)

	// Download artifacts from github:
	tmpDir, files, err := pub.DownloadArtifacts()
	if err != nil {
		log.Error().Err(err).Msg("error downloading artifacts")
		return
	}
	defer os.RemoveAll(tmpDir) // clean up

	log.Info().Msgf("downloaded artifacts to %s: %v", tmpDir, files)
	// Now we upload the SHASUMS files:

	err = pub.UploadSignatures(versionLinks, files)
	if err != nil {
		log.Error().Err(err).Msg("error uploading signatures")
		return
	}

	platformLinks, err := pub.CreatePlatforms(files)
	if err != nil {
		log.Error().Err(err).Msg("error creating platforms")
		return
	}

	err = pub.UploadPlatforms(platformLinks)
	if err != nil {
		log.Error().Err(err).Msg("error uploading platforms")
		return
	}
	log.Info().Msg("all done!")
	url := fmt.Sprintf(
		"https://app.terraform.io/app/%s/registry/providers/%s/%s/%s/latest/overview",
		providerConfig.TFOrganization,
		providerConfig.TFRegistryType,
		providerConfig.TFOrganization,
		providerConfig.ProviderName,
	)
	log.Info().Msgf("you should be able to see the new version at: %s", url)
}
