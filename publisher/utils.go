package publisher

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"os/exec"
	"strings"
)

/*
 * Run a command and decode the output as JSON into the provided struct.
 */
func runCommandJSON[T any](command string, outStruct *T) error {
	cmdArgs := strings.Split(command, " ")
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Error().Err(err).Msg("Error creating stdout pipe")
		return err
	}

	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("Error starting command")
		return err
	}

	if err := json.NewDecoder(stdOut).Decode(&outStruct); err != nil {
		log.Error().Err(err).Msg("Error decoding JSON")
		return err
	}
	if err := cmd.Wait(); err != nil {
		log.Error().Err(err).Msg("Error waiting for command to finish")
		return err
	}
	return nil
}

func getFileSha256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
