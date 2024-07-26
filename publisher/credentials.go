package publisher

import (
	"github.com/rs/zerolog/log"
	"github.com/tidwall/gjson"
	"io"
	"os"
	"os/user"
	"path"
)

func GetToken() string {
	log.Info().Msg("Checking 1password for token via tag 'terraform-tfc-token'...")
	token := ReadTokenFromOnePassword()
	if token == "" {
		log.Warn().Msg("token not found in 1password, trying credentials file...")
		currentUser, err := user.Current()
		if err != nil {
			log.Fatal().Err(err).Msg("Error getting current user")
		}
		credentialsPath := path.Join(currentUser.HomeDir, ".terraform.d/credentials.tfrc.json")
		token = ReadCredentialsFile(credentialsPath)
	}
	if token == "" {
		log.Warn().Msg("token not found in credentials file, trying env var...")
		token = ReadTokenFromEnv()
	}
	if token == "" {
		log.Error().Msg("No token found")
	}
	return token
}

func ReadTokenFromEnv() string {
	return os.Getenv("TF_TOKEN_app_terraform_io")
}

func ReadCredentialsFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		log.Print("Error opening credentials file: ", err)
		return ""
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		log.Print("Error reading credentials file: ", err)
		return ""
	}

	token := gjson.GetBytes(fileBytes, "credentials").Map()["app.terraform.io"].Map()["token"].String()
	return token
}
