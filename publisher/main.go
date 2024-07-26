package publisher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const _urlPrefix = "https://app.terraform.io/api/v2"

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
}

type Platform struct {
	// TODO: make this a matrix and generate the combinations?
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Config struct {
	RepositoryPath  string     `json:"repository_path"`
	TFOrganization  string     `json:"terraform_organization"`
	ProviderName    string     `json:"provider_name"`
	ProviderVersion string     `json:"provider_version"`
	GPGKeyId        string     `json:"gpg_key_id"`
	Platforms       []Platform `json:"supported_platforms"`
	TFRegistryType  string     `json:"terraform_registry_type"`
	Token           string
	Client          http.Client
}

type Publisher struct {
	Config Config
	Client http.Client
}

type VersionLinks struct {
	ShasumsUpload    string `json:"shasums-upload,omitempty"`
	ShasumsSigUpload string `json:"shasums-sig-upload,omitempty"`
}

type PlatformLinks struct {
	ProviderBinaryUpload string `json:"provider-binary-upload,omitempty"`
}

type VersionResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Version            string          `json:"version"`
			CreatedAt          string          `json:"created-at"`
			UpdatedAt          string          `json:"updated-at"`
			KeyID              string          `json:"key-id"`
			Protocols          []string        `json:"protocols"`
			Permissions        map[string]bool `json:"permissions"`
			ShasumsUploaded    bool            `json:"shasums-uploaded"`
			ShasumsSigUploaded bool            `json:"shasums-sig-uploaded"`
		}
		Relationships map[string]interface{} `json:"relationships"`
		Links         VersionLinks           `json:"links"`
	} `json:"data"`
}

type PlatformResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			OS                     string          `json:"os"`
			Arch                   string          `json:"arch"`
			Shasum                 string          `json:"shasum"`
			Filename               string          `json:"filename"`
			Permissions            map[string]bool `json:"permissions"`
			ProviderBinaryUploaded bool            `json:"provider-binary-uploaded"`
		}
		Relationships map[string]interface{} `json:"relationships"`
		Links         PlatformLinks          `json:"links"`
	}
}
type NeedsVersionUpload struct {
	NeedsShasums    bool
	NeedsShasumsSig bool
	Links           *VersionLinks
}

type NeedsPlatformUpload struct {
	NeedsBinary bool
	Links       *PlatformLinks
}

func buildProviderPayload(name, org, regType string) map[string]interface{} {
	return map[string]interface{}{
		"data": map[string]interface{}{
			"type": "registry-providers",
			"attributes": map[string]interface{}{
				"name":          name,
				"namespace":     org,
				"registry-name": regType,
			},
		},
	}
}

func buildVersionPayload(version, keyID string) map[string]interface{} {
	return map[string]interface{}{
		"data": map[string]interface{}{
			"type": "registry-provider-versions",
			"attributes": map[string]interface{}{
				"version":   version,
				"key-id":    keyID,
				"protocols": []string{"5.0"},
			},
		},
	}
}

func buildPlatformPayload(sha256, os, arch, filename string) map[string]interface{} {
	return map[string]interface{}{
		"data": map[string]interface{}{
			"type": "registry-provider-version-platforms",
			"attributes": map[string]interface{}{
				"os":       os,
				"arch":     arch,
				"shasum":   sha256,
				"filename": filepath.Base(filename),
			},
		},
	}
}

// Post sends a POST request to the given URL with the given io.Reader data
func (p *Publisher) Post(url string, data io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, data)
	req.Header.Add("Authorization", "Bearer "+p.Config.Token)
	req.Header.Add("Content-Type", "application/vnd.api+json")
	if err != nil {
		return nil, err
	}
	return p.Client.Do(req)
}

// Put sends a PUT request to the given URL with the given io.Reader data
func (p *Publisher) Put(url string, data io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, url, data)
	req.Header.Add("Authorization", "Bearer "+p.Config.Token)
	req.Header.Add("Content-Type", "application/vnd.api+json")
	if err != nil {
		return nil, err
	}
	return p.Client.Do(req)
}

// PostPayload sends a POST request to the given URL with the given map[string]interface{} payload
func (p *Publisher) PostPayload(url string, payload map[string]interface{}) (*http.Response, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(payload)
	if err != nil {
		log.Error().Err(err).Msg("error encoding payload")
	}
	return p.Post(url, &buf)
}

func (p *Publisher) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Add("Authorization", "Bearer "+p.Config.Token)
	req.Header.Add("Content-Type", "application/vnd.api+json")
	if err != nil {
		return nil, err
	}
	return p.Client.Do(req)
}

func (p *Publisher) GetProvider() error {
	// GET /organizations/:organization_name/registry-providers/:registry_name/:namespace/:name
	url := fmt.Sprintf(
		"%s/organizations/%s/registry-providers/%s/%s/%s",
		_urlPrefix,
		p.Config.TFOrganization,
		p.Config.TFRegistryType,
		p.Config.TFOrganization,
		p.Config.ProviderName,
	)
	resp, err := p.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not get provider: %s", resp.Status)
	}
	log.Info().Msg("provider exists")
	return nil
}

func (p *Publisher) CreateProvider() error {
	providerPayload := buildProviderPayload(p.Config.ProviderName, p.Config.TFOrganization, p.Config.TFRegistryType)
	// Send the request:
	// POST /organizations/:organization/registry-providers
	url := fmt.Sprintf("%s/organizations/%s/registry-providers", _urlPrefix, p.Config.TFOrganization)
	resp, err := p.PostPayload(url, providerPayload)
	if err != nil {
		return err
	}
	statusCode := resp.StatusCode
	if statusCode == http.StatusUnprocessableEntity {
		log.Warn().Msg("provider already exists")
		return nil
	}
	if statusCode != http.StatusCreated {
		return fmt.Errorf("could not create provider: %s", resp.Status)
	}
	log.Info().Msg("provider created successfully")
	return nil
}

func (p *Publisher) CreateVersion() (*NeedsVersionUpload, error) {
	versionPayload := buildVersionPayload(p.Config.ProviderVersion, p.Config.GPGKeyId)
	// Send the request:
	// POST /organizations/:organization/registry-providers/:reg-type/:organization/:name/versions
	url := fmt.Sprintf(
		"%s/organizations/%s/registry-providers/%s/%s/%s/versions",
		_urlPrefix,
		p.Config.TFOrganization,
		p.Config.TFRegistryType,
		p.Config.TFOrganization,
		p.Config.ProviderName,
	)
	resp, err := p.PostPayload(url, versionPayload)
	if err != nil {
		return nil, err
	}
	statusCode := resp.StatusCode
	if statusCode == http.StatusUnprocessableEntity {
		log.Warn().Msg("version already exists")
		return p.GetVersion()
	}
	if statusCode != http.StatusCreated {
		return nil, fmt.Errorf("could not create version: %s", resp.Status)
	}
	log.Info().Msg("version created successfully")

	var versionResponse VersionResponse
	err = json.NewDecoder(resp.Body).Decode(&versionResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse response: %v", err)
	}
	needsUpload := NeedsVersionUpload{
		NeedsShasums:    !versionResponse.Data.Attributes.ShasumsUploaded,
		NeedsShasumsSig: !versionResponse.Data.Attributes.ShasumsSigUploaded,
		Links:           &versionResponse.Data.Links,
	}
	return &needsUpload, nil
}

func (p *Publisher) GetVersion() (*NeedsVersionUpload, error) {
	// GET /organizations/:organization_name/registry-providers/:registry_name/:namespace/:name/versions/:version
	url := fmt.Sprintf(
		"%s/organizations/%s/registry-providers/%s/%s/%s/versions/%s",
		_urlPrefix,
		p.Config.TFOrganization,
		p.Config.TFRegistryType,
		p.Config.TFOrganization,
		p.Config.ProviderName,
		p.Config.ProviderVersion,
	)
	resp, err := p.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not get version: %s", resp.Status)
	}
	log.Info().Msg("version exists")
	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	//var versionResponse VersionResponse
	//err = json.NewDecoder(resp.Body).Decode(&versionResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse response: %v", err)
	}
	needsUpload := NeedsVersionUpload{
		//NeedsShasums:    !versionResponse.Data.Attributes.ShasumsUploaded,
		//NeedsShasumsSig: !versionResponse.Data.Attributes.ShasumsSigUploaded,
		//Links:           &versionResponse.Data.Links,
	}

	return &needsUpload, nil
}

func (p *Publisher) DownloadArtifacts() (string, []string, error) {
	downloaded := []string{}
	dir, err := os.MkdirTemp("", "nexus-publisher-*")
	if err != nil {
		log.Error().Err(err).Msg("error creating temp dir")
		return dir, downloaded, err
	}
	log.Info().Msgf("created temp dir: %s", dir)
	// download the artifacts
	url := fmt.Sprintf(
		"https://github.com/%s/releases/download/v%s/",
		p.Config.RepositoryPath,
		p.Config.ProviderVersion,
	)
	artifact_prefix := fmt.Sprintf("terraform-provider-%s_%s", p.Config.ProviderName, p.Config.ProviderVersion)
	artifacts := []string{
		artifact_prefix + "_SHA256SUMS",
		artifact_prefix + "_SHA256SUMS.sig",
	}
	for _, platform := range p.Config.Platforms {
		artifact := fmt.Sprintf("%s_%s_%s.zip", artifact_prefix, platform.OS, platform.Arch)
		artifacts = append(artifacts, artifact)
	}
	log.Info().Msgf("downloading artifacts: %v", artifacts)
	for _, artifact := range artifacts {
		// Use anon function to support defer better
		func() {
			getURL := url + artifact
			log.Info().Msgf("downloading %s", getURL)
			resp, err := p.Client.Get(getURL)
			if err != nil || resp.StatusCode != http.StatusOK {
				log.Error().Err(err).Msgf("error downloading artifact: %s", resp.Status)
				return
			}
			defer resp.Body.Close()
			file := filepath.Join(dir, artifact)
			out, err := os.Create(file)
			if err != nil {
				log.Error().Err(err).Msg("error creating file")
				return
			}
			defer out.Close()
			_, err = io.Copy(out, resp.Body)
			if err != nil {
				log.Error().Err(err).Msg("error writing file")
				return
			}
			log.Info().Msgf("downloaded %s", file)
			downloaded = append(downloaded, file)
		}()
	}
	log.Info().Msgf("downloaded %d artifacts", len(downloaded))
	return dir, downloaded, nil
}

func (p *Publisher) UploadFile(url, file string) error {
	log.Info().Msgf("uploading %s", file)
	// Open the file
	f, err := os.Open(file)
	if err != nil {
		log.Error().Err(err).Msg("error opening file")
		return err
	}
	defer f.Close()

	resp, err := p.Put(url, f)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Error().Err(err).Msgf("error uploading file: %s", resp.Status)
		return err
	}
	return nil
}

func (p *Publisher) UploadSignatures(links *NeedsVersionUpload, files []string) error {
	errors := []error{}
	for _, file := range files {
		func() {
			if strings.HasSuffix(file, "SHA256SUMS.sig") && links.NeedsShasumsSig {
				url := links.Links.ShasumsSigUpload
				if url == "" {
					log.Error().Msg("no signature upload URL")
					return
				}
				errors = append(errors, p.UploadFile(url, file))
			}
			if strings.HasSuffix(file, "SHA256SUMS") && links.NeedsShasums {
				url := links.Links.ShasumsUpload
				if url == "" {
					log.Error().Msg("no shasums upload URL")
					return
				}
				errors = append(errors, p.UploadFile(url, file))
			}
		}()
	}
	if len(errors) > 0 {
		return fmt.Errorf("errors uploading signatures: %v", errors)
	}
	return nil
}

func (p *Publisher) buildPlatformFileMap(files []string) map[string]string {
	platformToFile := map[string]string{}
	for _, file := range files {
		if !strings.HasSuffix(file, ".zip") {
			continue
		}
		basename := filepath.Base(file)
		pext := strings.Join(strings.Split(basename, "_")[2:], "_")
		platform := strings.TrimSuffix(pext, ".zip")
		platformToFile[platform] = file
	}
	output := map[string]string{}
	for _, platform := range p.Config.Platforms {
		key := fmt.Sprintf("%s_%s", platform.OS, platform.Arch)
		output[key] = platformToFile[key]
	}
	return output
}

func (p *Publisher) GetPlatform(os, arch string) (*NeedsPlatformUpload, error) {
	// GET /organizations/:organization_name/registry-providers/:registry_name/:namespace/:name/versions/:version/platforms/:os/:arch
	url := fmt.Sprintf(
		"%s/organizations/%s/registry-providers/%s/%s/%s/versions/%s/platforms/%s/%s",
		_urlPrefix,
		p.Config.TFOrganization,
		p.Config.TFRegistryType,
		p.Config.TFOrganization,
		p.Config.ProviderName,
		p.Config.ProviderVersion,
		os,
		arch,
	)
	resp, err := p.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not get platform: %s", resp.Status)
	}
	log.Info().Msg("platform exists")
	var platformResponse PlatformResponse
	err = json.NewDecoder(resp.Body).Decode(&platformResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse response: %v", err)
	}
	needsUpload := NeedsPlatformUpload{
		NeedsBinary: !platformResponse.Data.Attributes.ProviderBinaryUploaded,
		Links:       &platformResponse.Data.Links,
	}
	return &needsUpload, nil
}

func (p *Publisher) CreatePlatforms(files []string) (*map[string]NeedsPlatformUpload, error) {
	platformLinks := map[string]NeedsPlatformUpload{}
	for platform, file := range p.buildPlatformFileMap(files) {
		sha, err := getFileSha256(file)
		if err != nil {
			log.Error().Err(err).Msg("error getting sha256")
			return nil, err
		}
		log.Info().Msgf("sha256 of %s: %s", file, sha)
		platformChunks := strings.Split(platform, "_")
		platformOS := platformChunks[0]
		platformArch := platformChunks[1]
		platformPayload := buildPlatformPayload(sha, platformOS, platformArch, file)

		// Send the request:
		// POST /organizations/:organization/registry-providers/:reg-type/:organization/:name/versions/:version/platforms
		url := fmt.Sprintf(
			"%s/organizations/%s/registry-providers/%s/%s/%s/versions/%s/platforms",
			_urlPrefix,
			p.Config.TFOrganization,
			p.Config.TFRegistryType,
			p.Config.TFOrganization,
			p.Config.ProviderName,
			p.Config.ProviderVersion,
		)
		resp, err := p.PostPayload(url, platformPayload)
		if resp.StatusCode == http.StatusUnprocessableEntity {
			log.Warn().Msg("platform already exists")
			platformLink, err := p.GetPlatform(platformOS, platformArch)
			if err != nil {
				return nil, err
			}
			platformLinks[file] = *platformLink
			log.Info().Msg("retrieved existing platform info")
			continue
		}
		if err != nil || resp.StatusCode != http.StatusCreated {
			return nil, fmt.Errorf("could not create platform: %s", resp.Status)
		}

		var platformResponse PlatformResponse
		err = json.NewDecoder(resp.Body).Decode(&platformResponse)
		if err != nil {
			return nil, fmt.Errorf("could not parse response: %v", err)
		}
		platformLinks[file] = NeedsPlatformUpload{
			NeedsBinary: !platformResponse.Data.Attributes.ProviderBinaryUploaded,
			Links:       &platformResponse.Data.Links,
		}
		log.Info().Msg("platform created successfully")
	}
	log.Info().Msgf("created %d platforms", len(platformLinks))
	return &platformLinks, nil
}

func (p *Publisher) UploadPlatforms(platformLinks *map[string]NeedsPlatformUpload) error {
	errors := []error{}
	for file, links := range *platformLinks {
		func() {
			if links.NeedsBinary {
				err := p.UploadFile(links.Links.ProviderBinaryUpload, file)
				if err != nil {
					errors = append(errors, err)
					return
				}
			}
		}()
	}
	if len(errors) > 0 {
		return fmt.Errorf("errors uploading platforms: %v", errors)
	}
	return nil
}
