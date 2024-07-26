package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/datadrivers/terraform-provider-nexus/publisher"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	debug := flag.Bool("v", false, "sets verbose")
	pretty := flag.Bool("c", false, "sets pretty output")
	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if *pretty {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	}

	// get the auth token
	token := publisher.GetToken()

	// set up the client with headers etc
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	providerConfig := publisher.Config{
		RepositoryPath:  "octoenergy/terraform-provider-nexus",
		TFOrganization:  "octopus",
		ProviderName:    "nexus",
		ProviderVersion: "2.4.0-rc2-bump",
		GPGKeyId:        "AB1F45DCE1DDA2FE",
		Platforms: []publisher.Platform{
			{OS: "linux", Arch: "amd64"},
			{OS: "linux", Arch: "arm64"},
			{OS: "darwin", Arch: "amd64"},
			{OS: "darwin", Arch: "arm64"},
			{OS: "windows", Arch: "amd64"},
			{OS: "windows", Arch: "arm64"},
		},
		TFRegistryType: "private",
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
	}
	log.Info().Msg("provider created")

	versionLinks, err := pub.CreateVersion()
	if err != nil {
		log.Error().Err(err).Msg("error creating version")
	}
	log.Info().Msgf("version created, versionLinks: %v", versionLinks)

	// Download artifacts from github:
	tmpDir, files, err := pub.DownloadArtifacts()
	if err != nil {
		log.Error().Err(err).Msg("error downloading artifacts")
	}
	defer os.RemoveAll(tmpDir) // clean up

	log.Info().Msgf("downloaded artifacts to %s: %v", tmpDir, files)
	// Now we upload the SHASUMS files:

	err = pub.UploadSignatures(versionLinks, files)
	if err != nil {
		log.Error().Err(err).Msg("error uploading signatures")
	}

	platformLinks, err := pub.CreatePlatforms(files)
	if err != nil {
		log.Error().Err(err).Msg("error creating platforms")
	}

	err = pub.UploadPlatforms(platformLinks)
	if err != nil {
		log.Error().Err(err).Msg("error uploading platforms")
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
